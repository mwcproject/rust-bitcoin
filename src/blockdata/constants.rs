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

//! Blockdata constants
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction
//!

use crate::hashes::hex;
use crate::blockdata::opcodes;
use crate::blockdata::script;
use crate::blockdata::transaction::{OutPoint, Transaction, TxOut, TxIn};
use crate::blockdata::block::{Block, BlockHeader};
use crate::network::constants::Network;
use crate::util::uint::Uint256;

/// The maximum allowable sequence number
pub const MAX_SEQUENCE: u32 = 0xFFFFFFFF;
/// How many satoshis are in "one bitcoin"
pub const COIN_VALUE: u64 = 100_000_000;
/// How many seconds between blocks we expect on average
pub const TARGET_BLOCK_SPACING: u32 = 600;
/// How many blocks between diffchanges
pub const DIFFCHANGE_INTERVAL: u32 = 2016;
/// How much time on average should occur between diffchanges
pub const DIFFCHANGE_TIMESPAN: u32 = 14 * 24 * 3600;
/// The maximum allowed weight for a block, see BIP 141 (network rule)
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;
/// The factor that non-witness serialization data is multiplied by during weight calculation
pub const WITNESS_SCALE_FACTOR: usize = 4;


/// In Bitcoind this is insanely described as ~((u256)0 >> 32)
pub fn max_target(_: Network) -> Uint256 {
    Uint256([0xFFFF, 0, 0, 0]) << 208
}

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub fn max_money(_: Network) -> u64 {
    21_000_000 * COIN_VALUE
}

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block
fn bitcoin_genesis_tx() -> Result<Transaction, script::Error> {
    // Base
    let mut ret = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new().push_scriptint(486604799)?
                                          .push_scriptint(4)?
                                          .push_slice(b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")?
                                          .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: MAX_SEQUENCE,
        witness: vec![],
    });

    // Outputs
    let out_script = script::Builder::new()
        .push_slice(&hex::decode_to_vec("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")?)?
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    ret.output.push(TxOut {
        value: 50 * COIN_VALUE,
        script_pubkey: out_script
    });

    // end
    Ok(ret)
}

/// Constructs and returns the genesis block
pub fn genesis_block(network: Network) -> Result<Block, script::Error> {
    let txdata = vec![bitcoin_genesis_tx()?];
    let merkle_root = txdata[0].txid()
        .map_err(|_| script::Error::SerializationError)?
        .to_byte_array();
    let merkle_root = crate::hash_types::TxMerkleNode::from_byte_array(merkle_root);
    match network {
        Network::Bitcoin => {
            Ok(Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: crate::hash_types::BlockHash::from_byte_array([0u8; 32]),
                    merkle_root,
                    time: 1231006505,
                    bits: 0x1d00ffff,
                    nonce: 2083236893
                },
                txdata: txdata
            })
        }
        Network::Testnet => {
            Ok(Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: crate::hash_types::BlockHash::from_byte_array([0u8; 32]),
                    merkle_root,
                    time: 1296688602,
                    bits: 0x1d00ffff,
                    nonce: 414098458
                },
                txdata: txdata
            })
        }
        Network::Signet => {
            Ok(Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: crate::hash_types::BlockHash::from_byte_array([0u8; 32]),
                    merkle_root,
                    time: 1598918400,
                    bits: 0x1e0377ae,
                    nonce: 52613770
                },
                txdata: txdata
            })
        }
        Network::Regtest => {
            Ok(Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: crate::hash_types::BlockHash::from_byte_array([0u8; 32]),
                    merkle_root,
                    time: 1296688602,
                    bits: 0x207fffff,
                    nonce: 2
                },
                txdata: txdata
            })
        }
    }
}

#[cfg(test)]
mod test {
    use crate::hash_types::{BlockHash, Txid};
    use crate::hashes::hex;

    use crate::network::constants::Network;
    use crate::consensus::encode::serialize;
    use crate::blockdata::constants::{genesis_block, bitcoin_genesis_tx};
    use crate::blockdata::constants::{MAX_SEQUENCE, COIN_VALUE};

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let genesis = bitcoin_genesis_tx().unwrap();

        assert_eq!(genesis.version, 1);
        assert_eq!(genesis.input.len(), 1);
        assert_eq!(genesis.input[0].previous_output.txid, Txid::from_byte_array([0u8; 32]));
        assert_eq!(genesis.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&genesis.input[0].script_sig).unwrap(),
                   hex::decode_to_vec("4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap());

        assert_eq!(genesis.input[0].sequence, MAX_SEQUENCE);
        assert_eq!(genesis.output.len(), 1);
        assert_eq!(serialize(&genesis.output[0].script_pubkey).unwrap(),
                   hex::decode_to_vec("434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap());
        assert_eq!(genesis.output[0].value, 50 * COIN_VALUE);
        assert_eq!(genesis.lock_time, 0);

        assert_eq!(format!("{:x}", genesis.wtxid().unwrap()),
                   "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string());
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let genesis = genesis_block(Network::Bitcoin).unwrap();

        assert_eq!(genesis.header.version, 1);
        assert_eq!(genesis.header.prev_blockhash, BlockHash::from_byte_array([0u8; 32]));
        assert_eq!(format!("{:x}", genesis.header.merkle_root),
                   "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string());
        assert_eq!(genesis.header.time, 1231006505);
        assert_eq!(genesis.header.bits, 0x1d00ffff);
        assert_eq!(genesis.header.nonce, 2083236893);
        assert_eq!(format!("{:x}", genesis.header.block_hash().unwrap()),
                   "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f".to_string());
    }

    #[test]
    fn testnet_genesis_full_block() {
        let genesis = genesis_block(Network::Testnet).unwrap();
        assert_eq!(genesis.header.version, 1);
        assert_eq!(genesis.header.prev_blockhash, BlockHash::from_byte_array([0u8; 32]));
        assert_eq!(format!("{:x}", genesis.header.merkle_root),
                  "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string());
        assert_eq!(genesis.header.time, 1296688602);
        assert_eq!(genesis.header.bits, 0x1d00ffff);
        assert_eq!(genesis.header.nonce, 414098458);
        assert_eq!(format!("{:x}", genesis.header.block_hash().unwrap()),
                   "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943".to_string());
    }

    #[test]
    fn signet_genesis_full_block() {
        let genesis = genesis_block(Network::Signet).unwrap();
        assert_eq!(genesis.header.version, 1);
        assert_eq!(genesis.header.prev_blockhash, BlockHash::from_byte_array([0u8; 32]));
        assert_eq!(format!("{:x}", genesis.header.merkle_root),
                  "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string());
        assert_eq!(genesis.header.time, 1598918400);
        assert_eq!(genesis.header.bits, 0x1e0377ae);
        assert_eq!(genesis.header.nonce, 52613770);
        assert_eq!(format!("{:x}", genesis.header.block_hash().unwrap()),
                   "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6".to_string());
    }
}
