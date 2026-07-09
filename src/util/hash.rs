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

//! Hash functions
//!
//! Utility functions related to hashing data, including merkleization

use std::cmp::min;
use std::io;

use crate::hashes::{Hash, sha256d};
use crate::consensus::encode::Encodable;

/// Calculates the merkle root of a list of hashes inline
/// into the allocated slice.
///
/// In most cases, you'll want to use [bitcoin_merkle_root] instead.
pub fn bitcoin_merkle_root_inline<T>(data: &mut [T]) -> io::Result<T>
    where T: Hash<Bytes = [u8; 32]> + Encodable,
{
    // Base case
    if data.is_empty() {
        return Ok(T::from_byte_array([0u8; 32]));
    }
    if data.len() < 2 {
        return Ok(T::from_byte_array(data[0].to_byte_array()));
    }
    // Recursion
    for idx in 0..((data.len() + 1) / 2) {
        let idx1 = 2 * idx;
        let idx2 = min(idx1 + 1, data.len() - 1);
        let mut encoder = sha256d::Hash::engine();
        data[idx1].consensus_encode(&mut encoder)?;
        data[idx2].consensus_encode(&mut encoder)?;
        data[idx] = T::from_byte_array(sha256d::Hash::from_engine(encoder).to_byte_array());
    }
    let half_len = data.len() / 2 + data.len() % 2;
    bitcoin_merkle_root_inline(&mut data[0..half_len])
}

/// Calculates the merkle root of an iterator of hashes.
pub fn bitcoin_merkle_root<T, I>(mut iter: I) -> io::Result<T>
    where T: Hash<Bytes = [u8; 32]> + Encodable,
          I: ExactSizeIterator<Item = T>,
{
    // Base case
    if iter.len() == 0 {
        return Ok(T::from_byte_array([0u8; 32]));
    }
    if iter.len() == 1 {
        return match iter.next() {
            Some(hash) => Ok(T::from_byte_array(hash.to_byte_array())),
            None => Ok(T::from_byte_array([0u8; 32])),
        };
    }
    // Recursion
    let half_len = iter.len() / 2 + iter.len() % 2;
    let mut alloc = Vec::with_capacity(half_len);
    while let Some(hash1) = iter.next() {
        // If the size is odd, use the last element twice.
        let hash2 = iter.next().unwrap_or(hash1);
        let mut encoder = sha256d::Hash::engine();
        hash1.consensus_encode(&mut encoder)?;
        hash2.consensus_encode(&mut encoder)?;
        alloc.push(T::from_byte_array(sha256d::Hash::from_engine(encoder).to_byte_array()));
    }
    bitcoin_merkle_root_inline(&mut alloc)
}
