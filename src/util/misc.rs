// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Miscellaneous functions
//!
//! Various utility functions

use crate::hashes::{sha256d, HashEngine};

use crate::blockdata::opcodes;
use crate::consensus::{encode, Encodable};

#[cfg(feature = "secp-recovery")]
pub use self::message_signing::{MessageSignature, MessageSignatureError};

/// The prefix for signed messages using Bitcoin's message signing protocol.
pub const BITCOIN_SIGNED_MSG_PREFIX: &[u8] = b"\x18Bitcoin Signed Message:\n";

#[cfg(feature = "secp-recovery")]
mod message_signing {
    use std::{error, fmt};

    use crate::hashes::sha256d;
    use crate::secp256k1;
    use crate::secp256k1::{RecoveryId, RecoverableSignature};

    use crate::util::key::PublicKey;
    use crate::util::address::{Address, AddressType, Error as AddressError};

    /// An error used for dealing with Bitcoin Signed Messages.
    #[derive(Debug, PartialEq, Eq)]
    pub enum MessageSignatureError {
        /// Signature is expected to be 65 bytes.
        InvalidLength,
        /// The signature is invalidly constructed.
        InvalidEncoding(secp256k1::Error),
        /// Invalid base64 encoding.
        InvalidBase64,
    }

    impl fmt::Display for MessageSignatureError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match *self {
                MessageSignatureError::InvalidLength => write!(f, "length not 65 bytes"),
                MessageSignatureError::InvalidEncoding(ref e) => write!(f, "invalid encoding: {}", e),
                MessageSignatureError::InvalidBase64 => write!(f, "invalid base64"),
            }
        }
    }

    impl error::Error for MessageSignatureError {
        fn cause(&self) -> Option<&dyn error::Error> {
            None
        }
    }

    #[doc(hidden)]
    impl From<secp256k1::Error> for MessageSignatureError {
        fn from(e: secp256k1::Error) -> MessageSignatureError {
            MessageSignatureError::InvalidEncoding(e)
        }
    }

    /// A signature on a Bitcoin Signed Message.
    ///
    /// In order to use the `to_base64` and `from_base64` methods, as well as the
    /// `fmt::Display` and `str::FromStr` implementations, the `base64` feature
    /// must be enabled.
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub struct MessageSignature {
        /// The inner recoverable signature.
        pub signature: RecoverableSignature,
        /// Whether or not this signature was created with a compressed key.
        pub compressed: bool,
    }

    impl MessageSignature {
        /// Create a new [MessageSignature].
        pub fn new(signature: RecoverableSignature, compressed: bool) -> MessageSignature {
            MessageSignature {
                signature: signature,
                compressed: compressed,
            }
        }

        /// Serialize to bytes.
        pub fn serialize(&self) -> Result<[u8; 65], MessageSignatureError> {
            let secp = secp256k1::Secp256k1::new()?;
            let (recid, raw) = self.signature.serialize_compact(&secp)?;
            let mut serialized = [0u8; 65];
            let recid = u8::try_from(recid.to_i32())
                .map_err(|_| secp256k1::Error::InvalidRecoveryId)?;
            if recid > 3 {
                return Err(secp256k1::Error::InvalidRecoveryId.into());
            }
            serialized[0] = 27u8.checked_add(recid)
                .and_then(|header| if self.compressed { header.checked_add(4) } else { Some(header) })
                .ok_or(secp256k1::Error::InvalidRecoveryId)?;
            serialized[1..].copy_from_slice(&raw[..]);
            Ok(serialized)
        }

        /// Create from a byte slice.
        pub fn from_slice(bytes: &[u8]) -> Result<MessageSignature, MessageSignatureError> {
            if bytes.len() != 65 {
                return Err(MessageSignatureError::InvalidLength);
            }
            // We just check this here so we can safely subtract further.
            if bytes[0] < 27 {
                return Err(MessageSignatureError::InvalidEncoding(secp256k1::Error::InvalidRecoveryId));
            };
            let recid = RecoveryId::from_i32(((bytes[0] - 27) & 0x03) as i32)?;
            let secp = secp256k1::Secp256k1::new()?;
            Ok(MessageSignature {
                signature: RecoverableSignature::from_compact(&secp, &bytes[1..], recid)?,
                compressed: ((bytes[0] - 27) & 0x04) != 0,
            })
        }

        /// Attempt to recover a public key from the signature and the signed message.
        ///
        /// To get the message hash from a message, use [signed_msg_hash].
        pub fn recover_pubkey(
            &self,
            secp_ctx: &secp256k1::Secp256k1,
            msg_hash: sha256d::Hash
        ) -> Result<PublicKey, secp256k1::Error> {
            let msg = secp256k1::Message::from_slice(msg_hash.as_ref())?;
            let pubkey = secp_ctx.recover(&msg, &self.signature)?;
            Ok(PublicKey {
                key: pubkey,
                compressed: self.compressed,
            })
        }

        /// Verify that the signature signs the message and was signed by the given address.
        ///
        /// To get the message hash from a message, use [signed_msg_hash].
        pub fn is_signed_by_address(
            &self,
            secp_ctx: &secp256k1::Secp256k1,
            address: &Address,
            msg_hash: sha256d::Hash
        ) -> Result<bool, AddressError> {
            let pubkey = self.recover_pubkey(&secp_ctx, msg_hash)?;
            Ok(match address.address_type() {
                Some(AddressType::P2pkh) => {
                    *address == address.clone().p2pkh(secp_ctx, &pubkey, address.network)?
                }
                Some(AddressType::P2sh) => false,
                Some(AddressType::P2wpkh) => false,
                Some(AddressType::P2wsh) => false,
                None => false,
            })
        }

        #[cfg(feature = "base64")]
        /// Convert a signature from base64 encoding.
        pub fn from_base64(s: &str) -> Result<MessageSignature, MessageSignatureError> {
            let bytes = ::base64::decode(s).map_err(|_| MessageSignatureError::InvalidBase64)?;
            MessageSignature::from_slice(&bytes)
        }

        #[cfg(feature = "base64")]
        /// Convert to base64 encoding.
        pub fn to_base64(&self) -> Result<String, MessageSignatureError> {
            Ok(::base64::encode(&self.serialize()?[..]))
        }
    }

    #[cfg(feature = "base64")]
    impl fmt::Display for MessageSignature {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let bytes = self.serialize().map_err(|_| fmt::Error)?;
            // This avoids the allocation of a String.
            write!(f, "{}", ::base64::display::Base64Display::with_config(
                    &bytes[..], ::base64::STANDARD))
        }
    }

    #[cfg(feature = "base64")]
    impl ::std::str::FromStr for MessageSignature {
        type Err = MessageSignatureError;
        fn from_str(s: &str) -> Result<MessageSignature, MessageSignatureError> {
            MessageSignature::from_base64(s)
        }
    }
}

/// Search for `needle` in the vector `haystack` and remove every
/// instance of it, returning the number of instances removed.
/// Loops through the vector opcode by opcode, skipping pushed data.
pub fn script_find_and_remove(haystack: &mut Vec<u8>, needle: &[u8]) -> usize {
    if needle.len() > haystack.len() { return 0; }
    if needle.is_empty() { return 0; }

    let mut top = haystack.len() - needle.len();
    let mut n_deleted = 0;

    let mut i = 0;
    while i <= top {
        if &haystack[i..(i + needle.len())] == needle {
            for j in i..top {
                haystack.swap(j + needle.len(), j);
            }
            n_deleted += 1;
            // This is ugly but prevents infinite loop in case of overflow
            let overflow = top < needle.len();
            top = top.wrapping_sub(needle.len());
            if overflow { break; }
        } else {
            i += match opcodes::All::from((*haystack)[i]).classify() {
                opcodes::Class::PushBytes(n) => n as usize + 1,
                opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA1) => 2,
                opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA2) => 3,
                opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA4) => 5,
                _ => 1
            };
        }
    }
    haystack.truncate(top.wrapping_add(needle.len()));
    n_deleted
}

/// Hash message for signature using Bitcoin's message signing format.
pub fn signed_msg_hash(msg: &str) -> Result<sha256d::Hash, encode::Error> {
    let mut engine = sha256d::Hash::engine();
    engine.input(BITCOIN_SIGNED_MSG_PREFIX);
    let msg_len = encode::VarInt(msg.len() as u64);
    msg_len.consensus_encode(&mut engine)?;
    engine.input(msg.as_bytes());
    Ok(sha256d::Hash::from_engine(engine))
}

/// Helper function to convert hex nibble characters to their respective value
#[inline]
fn hex_val(c: u8) -> Result<u8, encode::Error> {
    let res = match c {
        b'0' ..= b'9' => c - '0' as u8,
        b'a' ..= b'f' => c - 'a' as u8 + 10,
        b'A' ..= b'F' => c - 'A' as u8 + 10,
        _ => return Err(encode::Error::UnexpectedHexDigit(c as char)),
    };
    Ok(res)
}

/// Convert a hexadecimal-encoded string to its corresponding bytes
pub fn hex_bytes(data: &str) -> Result<Vec<u8>, encode::Error> {
    // This code is optimized to be as fast as possible without using unsafe or platform specific
    // features. If you want to refactor it please make sure you don't introduce performance
    // regressions (run the benchmark with `cargo bench --features unstable`).

    // If the hex string has an uneven length fail early
    if data.len() % 2 != 0 {
        return Err(encode::Error::ParseFailed("hexstring of odd length"));
    }

    // Preallocate the uninitialized memory for the byte array
    let mut res = Vec::with_capacity(data.len() / 2);

    let mut hex_it = data.bytes();
    loop {
        // Get most significant nibble of current byte or end iteration
        let msn = match hex_it.next() {
            None => break,
            Some(x) => x,
        };

        // Get least significant nibble of current byte
        let lsn = match hex_it.next() {
            None => return Err(encode::Error::ParseFailed("hexstring of odd length")),
            Some(x) => x,
        };

        // Convert bytes representing characters to their represented value and combine lsn and msn.
        // The and_then and map are crucial for performance, in comparison to using ? and then
        // using the results of that for the calculation it's nearly twice as fast. Using bit
        // shifting and or instead of multiply and add on the other hand doesn't show a significant
        // increase in performance.
        match hex_val(msn).and_then(|msn_val| hex_val(lsn).map(|lsn_val| msn_val * 16 + lsn_val)) {
            Ok(x) => res.push(x),
            Err(e) => return Err(e),
        }
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::script_find_and_remove;
    use super::signed_msg_hash;

    #[test]
    fn test_script_find_and_remove() {
        let mut v = vec![101u8, 102, 103, 104, 102, 103, 104, 102, 103, 104, 105, 106, 107, 108, 109];

        assert_eq!(script_find_and_remove(&mut v, &[]), 0);
        assert_eq!(script_find_and_remove(&mut v, &[105, 105, 105]), 0);
        assert_eq!(v, vec![101, 102, 103, 104, 102, 103, 104, 102, 103, 104, 105, 106, 107, 108, 109]);

        assert_eq!(script_find_and_remove(&mut v, &[105, 106, 107]), 1);
        assert_eq!(v, vec![101, 102, 103, 104, 102, 103, 104, 102, 103, 104, 108, 109]);

        assert_eq!(script_find_and_remove(&mut v, &[104, 108, 109]), 1);
        assert_eq!(v, vec![101, 102, 103, 104, 102, 103, 104, 102, 103]);

        assert_eq!(script_find_and_remove(&mut v, &[101]), 1);
        assert_eq!(v, vec![102, 103, 104, 102, 103, 104, 102, 103]);

        assert_eq!(script_find_and_remove(&mut v, &[102]), 3);
        assert_eq!(v, vec![103, 104, 103, 104, 103]);

        assert_eq!(script_find_and_remove(&mut v, &[103, 104]), 2);
        assert_eq!(v, vec![103]);

        assert_eq!(script_find_and_remove(&mut v, &[105, 105, 5]), 0);
        assert_eq!(script_find_and_remove(&mut v, &[105]), 0);
        assert_eq!(script_find_and_remove(&mut v, &[103]), 1);
        assert_eq!(v, Vec::<u8>::new());

        assert_eq!(script_find_and_remove(&mut v, &[105, 105, 5]), 0);
        assert_eq!(script_find_and_remove(&mut v, &[105]), 0);
    }

    #[test]
    fn test_script_codesep_remove() {
        let mut s = vec![33u8, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 171, 33, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 171, 81];
        assert_eq!(script_find_and_remove(&mut s, &[171]), 2);
        assert_eq!(s, vec![33, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 33, 3, 132, 121, 160, 250, 153, 140, 211, 82, 89, 162, 239, 10, 122, 92, 104, 102, 44, 20, 116, 248, 140, 203, 109, 8, 167, 103, 123, 190, 199, 242, 32, 65, 173, 81]);
    }

    #[test]
    fn test_signed_msg_hash() {
        let hash = signed_msg_hash("test").unwrap();
        assert_eq!(hash.to_string(), "a6f87fe6d58a032c320ff8d1541656f0282c2c7bfcc69d61af4c8e8ed528e49c");
    }

    #[test]
    #[cfg(all(feature = "secp-recovery", feature = "base64"))]
    fn test_message_signature() {
        use std::str::FromStr;
        use crate::secp256k1;
        use crate::secp256k1::rand::rngs::SysRng;
        use crate::{Address, Network};

        let secp = secp256k1::Secp256k1::new().unwrap();
        let message = "rust-bitcoin MessageSignature test";
        let msg_hash = super::signed_msg_hash(&message).unwrap();
        let msg = secp256k1::Message::from_slice(msg_hash.as_ref()).unwrap();

        let privkey = secp256k1::SecretKey::new(&secp, &mut SysRng).unwrap();
        let secp_sig = secp.sign_recoverable(&msg, &privkey).unwrap();
        let signature = super::MessageSignature {
            signature: secp_sig,
            compressed: true,
        };

        assert_eq!(signature.to_base64().unwrap(), signature.to_string());
        let signature2 = super::MessageSignature::from_str(&signature.to_string()).unwrap();
        let pubkey = signature2.recover_pubkey(&secp, msg_hash).unwrap();
        assert_eq!(pubkey.compressed, true);
        assert_eq!(pubkey.key, secp256k1::PublicKey::from_secret_key(&secp, &privkey).unwrap());

        let p2pkh = Address::new_btc().p2pkh(&secp, &pubkey, Network::Bitcoin).unwrap();
        assert_eq!(signature2.is_signed_by_address(&secp, &p2pkh, msg_hash), Ok(true));
        let p2wpkh = Address::new_btc().p2wpkh(&secp, &pubkey, Network::Bitcoin).unwrap();
        assert_eq!(signature2.is_signed_by_address(&secp, &p2wpkh, msg_hash), Ok(false));
        let p2shwpkh = Address::new_btc().p2shwpkh(&secp, &pubkey, Network::Bitcoin).unwrap();
        assert_eq!(signature2.is_signed_by_address(&secp, &p2shwpkh, msg_hash), Ok(false));
    }
}
