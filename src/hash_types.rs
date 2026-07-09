// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! File defines types for hashes used throughout the library. These types are needed in order
//! to avoid mixing data of the same hash format (like SHA256d) but of different meaning
//! (transaction id, block hash etc).

use crate::hashes::{sha256, sha256d, hash160};

macro_rules! impl_hashencode {
    ($hashtype:ident) => {
        impl $crate::consensus::Encodable for $hashtype {
            fn consensus_encode<S: ::std::io::Write>(&self, s: S) -> Result<usize, ::std::io::Error> {
                self.to_byte_array().consensus_encode(s)
            }
        }

        impl $crate::consensus::Decodable for $hashtype {
            fn consensus_decode<D: ::std::io::Read>(d: D) -> Result<Self, $crate::consensus::encode::Error> {
                let bytes: [u8; 32] = $crate::consensus::Decodable::consensus_decode(d)?;
                Ok(Self::from_byte_array(bytes))
            }
        }
    };
}

hash_newtype! {
    /// A bitcoin transaction hash/transaction ID.
    pub struct Txid(pub sha256d::Hash);
    /// A bitcoin witness transaction ID.
    pub struct Wtxid(pub sha256d::Hash);
    /// A bitcoin block hash.
    pub struct BlockHash(pub sha256d::Hash);
    /// Hash of the transaction according to the signature algorithm.
    pub struct SigHash(pub sha256d::Hash);

    /// A hash of a public key.
    pub struct PubkeyHash(pub hash160::Hash);
    /// A hash of Bitcoin Script bytecode.
    pub struct ScriptHash(pub hash160::Hash);
    /// SegWit version of a public key hash.
    pub struct WPubkeyHash(pub hash160::Hash);
    /// SegWit version of a Bitcoin Script bytecode hash.
    pub struct WScriptHash(pub sha256::Hash);

    /// A hash of the Merkle tree branch or root for transactions.
    pub struct TxMerkleNode(pub sha256d::Hash);
    /// A hash corresponding to the Merkle tree root for witness data.
    pub struct WitnessMerkleNode(pub sha256d::Hash);
    /// A hash corresponding to the witness structure commitment in the coinbase transaction.
    pub struct WitnessCommitment(pub sha256d::Hash);
    /// XpubIdentifier as defined in BIP-32.
    pub struct XpubIdentifier(pub hash160::Hash);

    /// Filter hash, as defined in BIP-157.
    pub struct FilterHash(pub sha256d::Hash);
    /// Filter header, as defined in BIP-157.
    pub struct FilterHeader(pub sha256d::Hash);
}

impl_hex_for_newtype!(
    Txid, Wtxid, BlockHash, SigHash, PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash,
    TxMerkleNode, WitnessMerkleNode, WitnessCommitment, XpubIdentifier, FilterHash, FilterHeader
);

#[cfg(feature = "serde")]
impl_serde_for_newtype!(
    Txid, Wtxid, BlockHash, SigHash, PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash,
    TxMerkleNode, WitnessMerkleNode, WitnessCommitment, XpubIdentifier, FilterHash, FilterHeader
);

impl_hashencode!(Txid);
impl_hashencode!(Wtxid);
impl_hashencode!(SigHash);
impl_hashencode!(BlockHash);
impl_hashencode!(TxMerkleNode);
impl_hashencode!(WitnessMerkleNode);
impl_hashencode!(FilterHash);
impl_hashencode!(FilterHeader);
