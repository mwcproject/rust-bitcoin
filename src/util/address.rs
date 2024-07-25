// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Addresses
//!
//! Support for ordinary base58 Bitcoin addresses and private keys
//!
//! # Example: creating a new address from a randomly-generated key pair
//!
//! ```rust
//!
//! use bitcoin::network::constants::Network;
//! use bitcoin::util::address::Address;
//! use bitcoin::util::key;
//! use bitcoin::secp256k1::Secp256k1;
//! use bitcoin::secp256k1::rand::thread_rng;
//!
//! // Generate random key pair
//! let s = Secp256k1::new();
//! let public_key = key::PublicKey {
//!     compressed: true,
//!     key: s.generate_keypair(&mut thread_rng()).unwrap().1,
//! };
//!
//! // Generate pay-to-pubkey-hash address
//! let address = Address::new_btc().p2pkh(&s, &public_key, Network::Bitcoin);
//! ```

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;
use std::error;

use bech32;
use hashes::Hash;
use secp256k1::Secp256k1;
use hash_types::{PubkeyHash, WPubkeyHash, ScriptHash, WScriptHash};
use blockdata::script;
use network::constants::Network;
use util::base58;
use util::key;

/// Address error.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Base58 encoding error
    Base58(base58::Error),
    /// Bech32 encoding error
    Bech32(bech32::Error),
    /// The bech32 payload was empty
    EmptyBech32Payload,
    /// Script version must be 0 to 16 inclusive
    InvalidWitnessVersion(u8),
    /// The witness program must be between 2 and 40 bytes in length.
    InvalidWitnessProgramLength(usize),
    /// A v0 witness program must be either of length 20 or 32.
    InvalidSegwitV0ProgramLength(usize),
    /// An uncompressed pubkey was used where it is not allowed.
    UncompressedPubkey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Base58(ref e) => write!(f, "base58: {}", e),
            Error::Bech32(ref e) => write!(f, "bech32: {}", e),
            Error::EmptyBech32Payload => write!(f, "the bech32 payload was empty"),
            Error::InvalidWitnessVersion(v) => write!(f, "invalid witness script version: {}", v),
            Error::InvalidWitnessProgramLength(l) => write!(f,
                "the witness program must be between 2 and 40 bytes in length: length={}", l,
            ),
            Error::InvalidSegwitV0ProgramLength(l) => write!(f,
                "a v0 witness program must be either of length 20 or 32 bytes: length={}", l,
            ),
            Error::UncompressedPubkey => write!(f,
                "an uncompressed pubkey was used where it is not allowed",
            ),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Base58(ref e) => Some(e),
            Error::Bech32(ref e) => Some(e),
            _ => None,
        }
    }
}

#[doc(hidden)]
impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Error {
        Error::Base58(e)
    }
}

#[doc(hidden)]
impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Error {
        Error::Bech32(e)
    }
}

/// The different types of addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressType {
    /// pay-to-pubkey-hash
    P2pkh,
    /// pay-to-script-hash
    P2sh,
    /// pay-to-witness-pubkey-hash
    P2wpkh,
    /// pay-to-witness-script-hash
    P2wsh,
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            AddressType::P2pkh => "p2pkh",
            AddressType::P2sh => "p2sh",
            AddressType::P2wpkh => "p2wpkh",
            AddressType::P2wsh => "p2wsh",
        })
    }
}

impl FromStr for AddressType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "p2pkh" => Ok(AddressType::P2pkh),
            "p2sh" => Ok(AddressType::P2sh),
            "p2wpkh" => Ok(AddressType::P2wpkh),
            "p2wsh" => Ok(AddressType::P2wsh),
            _ => Err(()),
        }
    }
}

/// The method used to produce an address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Payload {
    /// P2PKH address
    PubkeyHash(PubkeyHash),
    /// P2SH address
    ScriptHash(ScriptHash),
    /// Segwit addresses
    WitnessProgram {
        /// The witness program version
        version: bech32::u5,
        /// The witness program
        program: Vec<u8>,
    },
}

impl Payload {
    /// Get a [Payload] from an output script (scriptPubkey).
    pub fn from_script(script: &script::Script) -> Option<Payload> {
        Some(if script.is_p2pkh() {
            Payload::PubkeyHash(PubkeyHash::from_slice(&script.as_bytes()[3..23]).unwrap())
        } else if script.is_p2sh() {
            Payload::ScriptHash(ScriptHash::from_slice(&script.as_bytes()[2..22]).unwrap())
        } else if script.is_witness_program() {
            // We can unwrap the u5 check and assume script length
            // because [Script::is_witness_program] makes sure of this.
            Payload::WitnessProgram {
                version: {
                    // Since we passed the [is_witness_program] check,
                    // the first byte is either 0x00 or 0x50 + version.
                    let mut verop = script.as_bytes()[0];
                    if verop > 0x50 {
                        verop -= 0x50;
                    }
                    bech32::u5::try_from_u8(verop).expect("checked before")
                },
                program: script.as_bytes()[2..].to_vec(),
            }
        } else {
            return None;
        })
    }

    /// Generates a script pubkey spending to this [Payload].
    pub fn script_pubkey(&self) -> script::Script {
        match *self {
            Payload::PubkeyHash(ref hash) =>
                script::Script::new_p2pkh(hash),
            Payload::ScriptHash(ref hash) =>
                script::Script::new_p2sh(hash),
            Payload::WitnessProgram {
                version: ver,
                program: ref prog,
            } => script::Script::new_witness_program(ver, prog)
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A Bitcoin address
pub struct Address {
    /// The type of the address
    pub payload: Payload,
    /// The network on which this address is usable
    pub network: Network,
    // Address can belog to different Coins. Befault is BTC.  Here are parameters that defines the address family.
    // https://github.com/libbitcoin/libbitcoin-system/wiki/Altcoin-Version-Mappings#bip44-altcoin-version-mapping-table
    /// Bech32 mainnet prefix
    pub prefix_bech32_mainnet: String,
    /// Bech32 testnet prefix
    pub prefix_bech32_testnet: String,
    /// Checksum: Mainnet Pubkey Hash address
    pub version_pubkeyhash_mainnet: Vec<u8>,
    /// Checksum: Testnet Pubkey Hash address
    pub version_pubkeyhash_testnet: Vec<u8>,
    /// Checksum: Mainnet Script Hash address
    pub version_scripthash_mainnet: Vec<u8>,
    /// Checksum: Testnet Script Hash address
    pub version_scripthash_testnet: Vec<u8>,
}
serde_string_impl!(Address, "a Bitcoin address");

impl Address {
    /// Create empty address as BTC
    pub fn new_btc() -> Address {
        Address {
            network: Network::Signet, // we don't don't support it, it is invalid value for MWC swaps
            payload: Payload::ScriptHash( ScriptHash::default() ),
            prefix_bech32_mainnet: "bc".to_string(),
            prefix_bech32_testnet: "tb".to_string(),
            version_pubkeyhash_mainnet: vec![0],
            version_scripthash_mainnet: vec![5],
            version_pubkeyhash_testnet: vec![111],
            version_scripthash_testnet: vec![196],
        }
    }

    /// Convert address to BTC syntax
    pub fn to_btc(self) -> Address {
        Address {
            network: self.network, // we don't don't support it, it is invalid value for MWC swaps
            payload: self.payload,
            prefix_bech32_mainnet: "bc".to_string(),
            prefix_bech32_testnet: "tb".to_string(),
            version_pubkeyhash_mainnet: vec![0],
            version_scripthash_mainnet: vec![5],
            version_pubkeyhash_testnet: vec![111],
            version_scripthash_testnet: vec![196],
        }
    }

    /// Create empty address to LTC syntax
    pub fn new_ltc() -> Address {
        Address {
            network: Network::Signet, // we don't don't support it, it is invalid value for MWC swaps
            payload: Payload::ScriptHash( ScriptHash::default() ),
            prefix_bech32_mainnet: "ltc".to_string(),
            prefix_bech32_testnet: "tltc".to_string(),
            version_pubkeyhash_mainnet: vec![48],
            version_scripthash_mainnet: vec![50],
            version_pubkeyhash_testnet: vec![111],
            version_scripthash_testnet: vec![58],
        }
    }

    /// Convert address to LTC syntax
    pub fn to_ltc(self) -> Address {
        Address {
            network: self.network, // we don't don't support it, it is invalid value for MWC swaps
            payload: self.payload,
            prefix_bech32_mainnet: "ltc".to_string(),
            prefix_bech32_testnet: "tltc".to_string(),
            version_pubkeyhash_mainnet: vec![48],
            version_scripthash_mainnet: vec![50],
            version_pubkeyhash_testnet: vec![111],
            version_scripthash_testnet: vec![58],
        }
    }

    /// Create empty address to LTC syntax
    pub fn new_dash() -> Address {
        Address {
            network: Network::Signet, // we don't don't support it, it is invalid value for MWC swaps
            payload: Payload::ScriptHash( ScriptHash::default() ),
            prefix_bech32_mainnet: "xxx".to_string(), // Dash doesn't support the segwit
            prefix_bech32_testnet: "xxx".to_string(),
            version_pubkeyhash_mainnet: vec![76],
            version_scripthash_mainnet: vec![16],
            version_pubkeyhash_testnet: vec![140],
            version_scripthash_testnet: vec![19],
        }
    }

    /// Convert address to LTC syntax
    pub fn to_dash(self) -> Address {
        Address {
            network: self.network, // we don't don't support it, it is invalid value for MWC swaps
            payload: self.payload,
            prefix_bech32_mainnet: "xxx".to_string(), // Dash doesn't support the segwit
            prefix_bech32_testnet: "xxx".to_string(),
            version_pubkeyhash_mainnet: vec![76],
            version_scripthash_mainnet: vec![16],
            version_pubkeyhash_testnet: vec![140],
            version_scripthash_testnet: vec![19],
        }
    }

    // https://zips.z.cash/protocol/protocol.pdf
    /// Create empty address to ZCash syntax
    pub fn new_zec() -> Address {
        Address {
            network: Network::Signet, // we don't don't support it, it is invalid value for MWC swaps
            payload: Payload::ScriptHash( ScriptHash::default() ),
            prefix_bech32_mainnet: "xxx".to_string(), // Dash doesn't support the segwit
            prefix_bech32_testnet: "xxx".to_string(),
            version_pubkeyhash_mainnet: vec![28,184],
            version_scripthash_mainnet: vec![28,189],
            version_pubkeyhash_testnet: vec![29,37],
            version_scripthash_testnet: vec![28,186],
        }
    }

    /// Convert address to ZCash syntax
    pub fn to_zec(self) -> Address {
        Address {
            network: self.network, // we don't don't support it, it is invalid value for MWC swaps
            payload: self.payload,
            prefix_bech32_mainnet: "xxx".to_string(), // Dash doesn't support the segwit
            prefix_bech32_testnet: "xxx".to_string(),
            version_pubkeyhash_mainnet: vec![28,184],
            version_scripthash_mainnet: vec![28,189],
            version_pubkeyhash_testnet: vec![29,37],
            version_scripthash_testnet: vec![28,186],
        }
    }

    /// Create empty address to Dogecoin syntax
    pub fn new_doge() -> Address {
        Address {
            network: Network::Signet, // we don't don't support it, it is invalid value for MWC swaps
            payload: Payload::ScriptHash( ScriptHash::default() ),
            prefix_bech32_mainnet: "xxx".to_string(), // Dash doesn't support the segwit
            prefix_bech32_testnet: "xxx".to_string(),
            version_pubkeyhash_mainnet: vec![30],
            version_scripthash_mainnet: vec![22],
            version_pubkeyhash_testnet: vec![113],
            version_scripthash_testnet: vec![196],
        }
    }

    /// Convert address to Dogecoin syntax
    pub fn to_doge(self) -> Address {
        Address {
            network: self.network, // we don't don't support it, it is invalid value for MWC swaps
            payload: self.payload,
            prefix_bech32_mainnet: "xxx".to_string(), // Dash doesn't support the segwit
            prefix_bech32_testnet: "xxx".to_string(),
            version_pubkeyhash_mainnet: vec![30],
            version_scripthash_mainnet: vec![22],
            version_pubkeyhash_testnet: vec![113],
            version_scripthash_testnet: vec![196],
        }
    }

    /// Creates a pay to (compressed) public key hash address from a public key
    /// This is the preferred non-witness type address
    #[inline]
    pub fn p2pkh(self, secp: &Secp256k1, pk: &key::PublicKey, network: Network) -> Address {
        let mut hash_engine = PubkeyHash::engine();
        pk.write_into(secp, &mut hash_engine).expect("engines don't error");

        Address {
            network: network,
            payload: Payload::PubkeyHash(PubkeyHash::from_engine(hash_engine)),
            prefix_bech32_mainnet: self.prefix_bech32_mainnet,
            prefix_bech32_testnet: self.prefix_bech32_testnet,
            version_pubkeyhash_mainnet: self.version_pubkeyhash_mainnet,
            version_scripthash_mainnet: self.version_scripthash_mainnet,
            version_pubkeyhash_testnet: self.version_pubkeyhash_testnet,
            version_scripthash_testnet: self.version_scripthash_testnet,
        }
    }

    /// Creates a pay to script hash P2SH address from a script
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig these days.
    #[inline]
    pub fn p2sh(self, script: &script::Script, network: Network) -> Address {
        Address {
            network: network,
            payload: Payload::ScriptHash(ScriptHash::hash(&script[..])),
            prefix_bech32_mainnet: self.prefix_bech32_mainnet,
            prefix_bech32_testnet: self.prefix_bech32_testnet,
            version_pubkeyhash_mainnet: self.version_pubkeyhash_mainnet,
            version_scripthash_mainnet: self.version_scripthash_mainnet,
            version_pubkeyhash_testnet: self.version_pubkeyhash_testnet,
            version_scripthash_testnet: self.version_scripthash_testnet,
        }
    }

    /// Create a witness pay to public key address from a public key
    /// This is the native segwit address type for an output redeemable with a single signature
    ///
    /// Will only return an Error when an uncompressed public key is provided.
    pub fn p2wpkh(self, secp: &Secp256k1, pk: &key::PublicKey, network: Network) -> Result<Address, Error> {
        if !pk.compressed {
            return Err(Error::UncompressedPubkey);
        }

        let mut hash_engine = WPubkeyHash::engine();
        pk.write_into(secp, &mut hash_engine).expect("engines don't error");

        Ok(Address {
            network: network,
            payload: Payload::WitnessProgram {
                version: bech32::u5::try_from_u8(0).expect("0<32"),
                program: WPubkeyHash::from_engine(hash_engine)[..].to_vec(),
            },
            prefix_bech32_mainnet: self.prefix_bech32_mainnet,
            prefix_bech32_testnet: self.prefix_bech32_testnet,
            version_pubkeyhash_mainnet: self.version_pubkeyhash_mainnet,
            version_scripthash_mainnet: self.version_scripthash_mainnet,
            version_pubkeyhash_testnet: self.version_pubkeyhash_testnet,
            version_scripthash_testnet: self.version_scripthash_testnet,
        })
    }

    /// Create a pay to script address that embeds a witness pay to public key
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients
    ///
    /// Will only return an Error when an uncompressed public key is provided.
    pub fn p2shwpkh(self, secp: &Secp256k1, pk: &key::PublicKey, network: Network) -> Result<Address, Error> {
        if !pk.compressed {
            return Err(Error::UncompressedPubkey);
        }

        let mut hash_engine = WPubkeyHash::engine();
        pk.write_into(secp, &mut hash_engine).expect("engines don't error");

        let builder = script::Builder::new()
            .push_int(0)
            .push_slice(&WPubkeyHash::from_engine(hash_engine)[..]);

        Ok(Address {
            network: network,
            payload: Payload::ScriptHash(ScriptHash::hash(builder.into_script().as_bytes())),
            prefix_bech32_mainnet: self.prefix_bech32_mainnet,
            prefix_bech32_testnet: self.prefix_bech32_testnet,
            version_pubkeyhash_mainnet: self.version_pubkeyhash_mainnet,
            version_scripthash_mainnet: self.version_scripthash_mainnet,
            version_pubkeyhash_testnet: self.version_pubkeyhash_testnet,
            version_scripthash_testnet: self.version_scripthash_testnet,
        })
    }

    /// Create a witness pay to script hash address
    pub fn p2wsh(self, script: &script::Script, network: Network) -> Address {
        Address {
            network: network,
            payload: Payload::WitnessProgram {
                version: bech32::u5::try_from_u8(0).expect("0<32"),
                program: WScriptHash::hash(&script[..])[..].to_vec(),
            },
            prefix_bech32_mainnet: self.prefix_bech32_mainnet,
            prefix_bech32_testnet: self.prefix_bech32_testnet,
            version_pubkeyhash_mainnet: self.version_pubkeyhash_mainnet,
            version_scripthash_mainnet: self.version_scripthash_mainnet,
            version_pubkeyhash_testnet: self.version_pubkeyhash_testnet,
            version_scripthash_testnet: self.version_scripthash_testnet,
        }
    }

    /// Create a pay to script address that embeds a witness pay to script hash address
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients
    pub fn p2shwsh(self, script: &script::Script, network: Network) -> Address {
        let ws = script::Builder::new()
            .push_int(0)
            .push_slice(&WScriptHash::hash(&script[..])[..])
            .into_script();

        Address {
            network: network,
            payload: Payload::ScriptHash(ScriptHash::hash(&ws[..])),
            prefix_bech32_mainnet: self.prefix_bech32_mainnet,
            prefix_bech32_testnet: self.prefix_bech32_testnet,
            version_pubkeyhash_mainnet: self.version_pubkeyhash_mainnet,
            version_scripthash_mainnet: self.version_scripthash_mainnet,
            version_pubkeyhash_testnet: self.version_pubkeyhash_testnet,
            version_scripthash_testnet: self.version_scripthash_testnet,
        }
    }

    /// Get the address type of the address.
    /// None if unknown or non-standard.
    pub fn address_type(&self) -> Option<AddressType> {
        match self.payload {
            Payload::PubkeyHash(_) => Some(AddressType::P2pkh),
            Payload::ScriptHash(_) => Some(AddressType::P2sh),
            Payload::WitnessProgram {
                version: ver,
                program: ref prog,
            } => {
                // BIP-141 p2wpkh or p2wsh addresses.
                match ver.to_u8() {
                    0 => match prog.len() {
                        20 => Some(AddressType::P2wpkh),
                        32 => Some(AddressType::P2wsh),
                        _ => None,
                    },
                    _ => None,
                }
            }
        }
    }

    /// Check whether or not the address is following Bitcoin
    /// standardness rules.
    ///
    /// Segwit addresses with unassigned witness versions or non-standard
    /// program sizes are considered non-standard.
    pub fn is_standard(&self) -> bool {
        self.address_type().is_some()
    }

    /// Get an [Address] from an output script (scriptPubkey).
    pub fn from_script(self, script: &script::Script, network: Network) -> Option<Address> {
        Some(Address {
            payload: Payload::from_script(script)?,
            network: network,
            prefix_bech32_mainnet: self.prefix_bech32_mainnet,
            prefix_bech32_testnet: self.prefix_bech32_testnet,
            version_pubkeyhash_mainnet: self.version_pubkeyhash_mainnet,
            version_scripthash_mainnet: self.version_scripthash_mainnet,
            version_pubkeyhash_testnet: self.version_pubkeyhash_testnet,
            version_scripthash_testnet: self.version_scripthash_testnet,
        })
    }

    /// Generates a script pubkey spending to this address
    pub fn script_pubkey(&self) -> script::Script {
        self.payload.script_pubkey()
    }

    /// Build address from the BTC address string.
    pub fn from_str(self, s: &str) -> Result<Address, Error> {
        // try bech32
        let prefix = find_bech32_prefix(s);
        let bech32_network = if self.prefix_bech32_testnet.eq_ignore_ascii_case(prefix) {
            Some(Network::Testnet)
        } else if self.prefix_bech32_mainnet.eq_ignore_ascii_case(prefix) {
            Some(Network::Bitcoin)
        } else {
            None
        };

        if let Some(network) = bech32_network {
            // decode as bech32
            let (_, payload) = bech32::decode(s)?;
            if payload.is_empty() {
                return Err(Error::EmptyBech32Payload);
            }

            // Get the script version and program (converted from 5-bit to 8-bit)
            let (version, program): (bech32::u5, Vec<u8>) = {
                let (v, p5) = payload.split_at(1);
                (v[0], bech32::FromBase32::from_base32(p5)?)
            };

            // Generic segwit checks.
            if version.to_u8() > 16 {
                return Err(Error::InvalidWitnessVersion(version.to_u8()));
            }
            if program.len() < 2 || program.len() > 40 {
                return Err(Error::InvalidWitnessProgramLength(program.len()));
            }

            // Specific segwit v0 check.
            if version.to_u8() == 0 && (program.len() != 20 && program.len() != 32) {
                return Err(Error::InvalidSegwitV0ProgramLength(program.len()));
            }

            return Ok(Address {
                payload: Payload::WitnessProgram {
                    version: version,
                    program: program,
                },
                network: network,
                prefix_bech32_mainnet: self.prefix_bech32_mainnet,
                prefix_bech32_testnet: self.prefix_bech32_testnet,
                version_pubkeyhash_mainnet: self.version_pubkeyhash_mainnet,
                version_scripthash_mainnet: self.version_scripthash_mainnet,
                version_pubkeyhash_testnet: self.version_pubkeyhash_testnet,
                version_scripthash_testnet: self.version_scripthash_testnet,
            });
        }

        // Base58
        if s.len() > 50 {
            return Err(Error::Base58(base58::Error::InvalidLength(s.len() * 11 / 15)));
        }
        let data = base58::from_check(s)?;
        let prefix_len = self.version_pubkeyhash_mainnet.len(); // All prefixes has the same length (1 or 2)
        if data.len() != 20+prefix_len {
            return Err(Error::Base58(base58::Error::InvalidLength(data.len())));
        }

        let version = data[0..prefix_len].to_vec();
        let (network, payload) = if version == self.version_pubkeyhash_mainnet {
            (
                Network::Bitcoin,
                Payload::PubkeyHash(PubkeyHash::from_slice(&data[prefix_len..]).unwrap()),
            )
        } else if version == self.version_scripthash_mainnet {
            (
                Network::Bitcoin,
                Payload::ScriptHash(ScriptHash::from_slice(&data[prefix_len..]).unwrap()),
            )
        } else if version == self.version_pubkeyhash_testnet {
            (
                Network::Testnet,
                Payload::PubkeyHash(PubkeyHash::from_slice(&data[prefix_len..]).unwrap()),
            )
        } else if version == self.version_scripthash_testnet {
            (
                Network::Testnet,
                Payload::ScriptHash(ScriptHash::from_slice(&data[prefix_len..]).unwrap()),
            )
        }
        else {
            return Err(Error::Base58(base58::Error::InvalidVersion(version)));
        };

        Ok(Address {
            network: network,
            payload: payload,
            prefix_bech32_mainnet: self.prefix_bech32_mainnet,
            prefix_bech32_testnet: self.prefix_bech32_testnet,
            version_pubkeyhash_mainnet: self.version_pubkeyhash_mainnet,
            version_scripthash_mainnet: self.version_scripthash_mainnet,
            version_pubkeyhash_testnet: self.version_pubkeyhash_testnet,
            version_scripthash_testnet: self.version_scripthash_testnet,
        })
    }
}

impl Display for Address {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        match self.payload {
            Payload::PubkeyHash(ref hash) => {
                let mut prefixed = match self.network {
                    Network::Bitcoin => self.version_pubkeyhash_mainnet.clone(),
                    Network::Testnet | Network::Signet | Network::Regtest => self.version_pubkeyhash_testnet.clone(),
                };
                prefixed.append( &mut hash[..].to_vec() );
                base58::check_encode_slice_to_fmt(fmt, &prefixed)
            }
            Payload::ScriptHash(ref hash) => {
                let mut prefixed = match self.network {
                    Network::Bitcoin => self.version_scripthash_mainnet.clone(),
                    Network::Testnet | Network::Signet | Network::Regtest => self.version_scripthash_testnet.clone(),
                };
                prefixed.append( &mut hash[..].to_vec() );
                base58::check_encode_slice_to_fmt(fmt, &prefixed)
            }
            Payload::WitnessProgram {
                version: ver,
                program: ref prog,
            } => {
                let hrp = match self.network {
                    Network::Bitcoin => self.prefix_bech32_mainnet.as_str(),
                    Network::Testnet | Network::Signet  => self.prefix_bech32_testnet.as_str(),
                    Network::Regtest => "bcrt",
                };
                let mut bech32_writer = bech32::Bech32Writer::new(hrp, fmt)?;
                bech32::WriteBase32::write_u5(&mut bech32_writer, ver)?;
                bech32::ToBase32::write_base32(&prog, &mut bech32_writer)
            }
        }
    }
}

/// Extract the bech32 prefix.
/// Returns the same slice when no prefix is found.
fn find_bech32_prefix(bech32: &str) -> &str {
    // Split at the last occurrence of the separator character '1'.
    match bech32.rfind('1') {
        None => bech32,
        Some(sep) => bech32.split_at(sep).0,
    }
}

impl ::std::fmt::Debug for Address {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::string::ToString;

    use hashes::hex::{FromHex, ToHex};
    use secp256k1::ContextFlag;

    use blockdata::script::Script;
    use network::constants::Network::{Bitcoin, Testnet};
    use util::key::PublicKey;

    use super::*;

    macro_rules! hex (($hex:expr) => (Vec::from_hex($hex).unwrap()));
    macro_rules! hex_key (($secp:expr, $hex:expr) => (PublicKey::from_slice($secp, &hex!($hex)).unwrap()));
    macro_rules! hex_script (($hex:expr) => (Script::from(hex!($hex))));
    macro_rules! hex_pubkeyhash (($hex:expr) => (PubkeyHash::from_hex(&$hex).unwrap()));
    macro_rules! hex_scripthash (($hex:expr) => (ScriptHash::from_hex($hex).unwrap()));

    fn roundtrips(addr: &Address) {
        assert_eq!(
            Address::new_btc().from_str(&addr.to_string()).unwrap(),
            *addr,
            "string round-trip failed for {}",
            addr,
        );
        assert_eq!(
            Address::new_btc().from_script(&addr.script_pubkey(), addr.network).as_ref(),
            Some(addr),
            "script round-trip failed for {}",
            addr,
        );
        //TODO: add serde roundtrip after no-strason PR
    }

    #[test]
    fn test_p2pkh_address_58() {
        let mut addr = Address::new_btc();
        addr.network = Bitcoin;
        addr.payload = Payload::PubkeyHash(hex_pubkeyhash!("162c5ea71c0b23f5b9022ef047c4a86470a5b070"));

        assert_eq!(
            addr.script_pubkey(),
            hex_script!("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac")
        );
        assert_eq!(&addr.to_string(), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2pkh_from_key() {
        let secp = Secp256k1::with_caps(ContextFlag::None);
        let key = hex_key!(&secp, "048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183");
        let addr = Address::new_btc().p2pkh(&secp, &key, Bitcoin);
        assert_eq!(&addr.to_string(), "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY");

        let key = hex_key!(&secp, &"03df154ebfcf29d29cc10d5c2565018bce2d9edbab267c31d2caf44a63056cf99f");
        let addr = Address::new_btc().p2pkh(&secp, &key, Testnet);
        assert_eq!(&addr.to_string(), "mqkhEMH6NCeYjFybv7pvFC22MFeaNT9AQC");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2sh_address_58() {
        let mut addr = Address::new_btc();
        addr.network = Bitcoin;
        addr.payload = Payload::ScriptHash(hex_scripthash!("162c5ea71c0b23f5b9022ef047c4a86470a5b070"));

        assert_eq!(
            addr.script_pubkey(),
            hex_script!("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087")
        );
        assert_eq!(&addr.to_string(), "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2sh_parse() {
        let script = hex_script!("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae");
        let addr = Address::new_btc().p2sh(&script, Testnet);

        assert_eq!(&addr.to_string(), "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2wpkh() {
        let secp = Secp256k1::with_caps(ContextFlag::None);
        // stolen from Bitcoin transaction: b3c8c2b6cfc335abbcb2c7823a8453f55d64b2b5125a9a61e8737230cdb8ce20
        let mut key = hex_key!(&secp, "033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc");
        let addr = Address::new_btc().p2wpkh(&secp, &key, Bitcoin).unwrap();
        assert_eq!(&addr.to_string(), "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw");
        assert_eq!(addr.address_type(), Some(AddressType::P2wpkh));
        roundtrips(&addr);

        // Test uncompressed pubkey
        key.compressed = false;
        assert_eq!(Address::new_btc().p2wpkh(&secp, &key, Bitcoin), Err(Error::UncompressedPubkey));
    }

    #[test]
    fn test_p2wsh() {
        // stolen from Bitcoin transaction 5df912fda4becb1c29e928bec8d64d93e9ba8efa9b5b405bd683c86fd2c65667
        let script = hex_script!("52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae");
        let addr = Address::new_btc().p2wsh(&script, Bitcoin);
        assert_eq!(
            &addr.to_string(),
            "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
        );
        assert_eq!(addr.address_type(), Some(AddressType::P2wsh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2shwpkh() {
        // stolen from Bitcoin transaction: ad3fd9c6b52e752ba21425435ff3dd361d6ac271531fc1d2144843a9f550ad01
        let secp = Secp256k1::with_caps(ContextFlag::None);
        let mut key = hex_key!(&secp, "026c468be64d22761c30cd2f12cbc7de255d592d7904b1bab07236897cc4c2e766");
        let addr = Address::new_btc().p2shwpkh(&secp, &key, Bitcoin).unwrap();
        assert_eq!(&addr.to_string(), "3QBRmWNqqBGme9er7fMkGqtZtp4gjMFxhE");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);

        // Test uncompressed pubkey
        key.compressed = false;
        assert_eq!(Address::new_btc().p2wpkh(&secp, &key, Bitcoin), Err(Error::UncompressedPubkey));
    }

    #[test]
    fn test_p2shwsh() {
        // stolen from Bitcoin transaction f9ee2be4df05041d0e0a35d7caa3157495ca4f93b233234c9967b6901dacf7a9
        let script = hex_script!("522103e5529d8eaa3d559903adb2e881eb06c86ac2574ffa503c45f4e942e2a693b33e2102e5f10fcdcdbab211e0af6a481f5532536ec61a5fdbf7183770cf8680fe729d8152ae");
        let addr = Address::new_btc().p2shwsh(&script, Bitcoin);
        assert_eq!(&addr.to_string(), "36EqgNnsWW94SreZgBWc1ANC6wpFZwirHr");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);
    }

    #[test]
    fn test_non_existent_segwit_version() {
        let version = 13;
        // 40-byte program
        let program = hex!(
            "654f6ea368e0acdfd92976b7c2103a1b26313f430654f6ea368e0acdfd92976b7c2103a1b26313f4"
        );
        let mut addr = Address::new_btc();
        addr.payload = Payload::WitnessProgram {
                version: bech32::u5::try_from_u8(version).expect("0<32"),
                program: program,
            };
        addr.network = Network::Bitcoin;
        roundtrips(&addr);
    }

    #[test]
    fn test_bip173_vectors() {
        let valid_vectors = [
            ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"),
            ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
            ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"),
            ("BC1SW50QA3JX3S", "6002751e"),
            ("bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", "5210751e76e8199196d454941c45d1b3a323"),
            ("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
        ];
        for vector in &valid_vectors {
            let addr: Address = Address::new_btc().from_str( vector.0 ).unwrap();
            assert_eq!(&addr.script_pubkey().as_bytes().to_hex(), vector.1);
            roundtrips(&addr);
        }

        let invalid_vectors = [
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
            "bc1rw5uspcuh",
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
            "bc1gmk9yu",
        ];
        for vector in &invalid_vectors {
            assert!( Address::new_btc().from_str(vector).is_err() );
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_json_serialize() {
        use serde_json;

        let addr = Address::new_btc().from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM").unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".to_owned())
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac")
        );

        let addr = Address::new_btc().from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k").unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k".to_owned())
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087")
        );

        let addr =
            Address::new_btc().from_str("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
                .unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String(
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_owned()
            )
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
        );

        let addr = Address::new_btc().from_str("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl").unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl".to_owned())
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("001454d26dddb59c7073c6a197946ea1841951fa7a74")
        );
    }
}
