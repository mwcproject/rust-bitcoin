// Rust Bitcoin Library
// Written in 2019 by
//     The rust-bitcoin developers.
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Taproot
//!

use crate::hashes::{sha256, sha256t};

/// The SHA-256 midstate value for the TapLeaf hash.
const MIDSTATE_TAPLEAF: [u8; 32] = [
    156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243, 147, 108,
    71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
];
// 9ce0e4e67c116c3938b3caf2c30f5089d3f3936c47636e607db33eeaddc6f0c9

/// The SHA-256 midstate value for the TapBranch hash.
const MIDSTATE_TAPBRANCH: [u8; 32] = [
    35, 168, 101, 169, 184, 164, 13, 167, 151, 124, 30, 4, 196, 158, 36, 111, 181, 190, 19, 118,
    157, 36, 201, 183, 181, 131, 181, 212, 168, 210, 38, 210,
];
// 23a865a9b8a40da7977c1e04c49e246fb5be13769d24c9b7b583b5d4a8d226d2

/// The SHA-256 midstate value for the TapTweak hash.
const MIDSTATE_TAPTWEAK: [u8; 32] = [
    209, 41, 162, 243, 112, 28, 101, 93, 101, 131, 182, 195, 185, 65, 151, 39, 149, 244, 226, 50,
    148, 253, 84, 244, 162, 174, 141, 133, 71, 202, 89, 11,
];
// d129a2f3701c655d6583b6c3b941972795f4e23294fd54f4a2ae8d8547ca590b

/// The SHA-256 midstate value for the TapSigHash hash.
const MIDSTATE_TAPSIGHASH: [u8; 32] = [
    245, 4, 164, 37, 215, 248, 120, 59, 19, 99, 134, 138, 227, 229, 86, 88, 110, 238, 148, 93, 188,
    120, 136, 221, 2, 166, 226, 195, 24, 115, 254, 159,
];
// f504a425d7f8783b1363868ae3e556586eee945dbc7888dd02a6e2c31873fe9f

/// Internal macro to speficy the different taproot tagged hashes.
macro_rules! sha256t_hash_newtype {
    ($newtype:ident, $tag:ident, $midstate:ident, $midstate_len:expr, $docs:meta, $reverse: expr) => {
        /// The tag used for [$newtype].
        pub struct $tag;

        impl sha256t::Tag for $tag {
            const MIDSTATE: sha256::Midstate = sha256::Midstate::new($midstate, $midstate_len);
        }

        impl $tag {
            /// Constructs a tagged hash engine.
            pub fn engine() -> sha256t::HashEngine<$tag> {
                sha256t::Hash::<$tag>::engine()
            }
        }

        hash_newtype! {
            #[$docs]
            #[hash_newtype(backward)]
            pub struct $newtype(pub sha256t::Hash<$tag>);
        }
        impl_hex_for_newtype!($newtype);
    };
}

// Currently all taproot hashes are defined as being displayed backwards,
// but that can be specified individually per hash.
sha256t_hash_newtype!(TapLeafHash, TapLeafTag, MIDSTATE_TAPLEAF, 64,
    doc = "Taproot-tagged hash for tapscript Merkle tree leafs", true
);
sha256t_hash_newtype!(TapBranchHash, TapBranchTag, MIDSTATE_TAPBRANCH, 64,
    doc = "Taproot-tagged hash for tapscript Merkle tree branches", true
);
sha256t_hash_newtype!(TapTweakHash, TapTweakTag, MIDSTATE_TAPTWEAK, 64,
    doc = "Taproot-tagged hash for public key tweaks", true
);
sha256t_hash_newtype!(TapSighashHash, TapSighashTag, MIDSTATE_TAPSIGHASH, 64,
    doc = "Taproot-tagged hash for the taproot signature hash", true
);

#[cfg(test)]
mod test {
    use super::*;
    use crate::hashes::{HashEngine, sha256};

    fn tag_engine(tag_name: &str) -> sha256::HashEngine {
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash(tag_name.as_bytes());
        engine.input(tag_hash.as_ref());
        engine.input(tag_hash.as_ref());
        engine
    }

    fn midstate_bytes(engine: sha256::HashEngine) -> [u8; 32] {
        engine
            .midstate()
            .unwrap()
            .to_parts()
            .0
    }

    #[test]
    fn test_midstates() {
        // check midstate against hard-coded values
        assert_eq!(MIDSTATE_TAPLEAF, midstate_bytes(tag_engine("TapLeaf")));
        assert_eq!(MIDSTATE_TAPBRANCH, midstate_bytes(tag_engine("TapBranch")));
        assert_eq!(MIDSTATE_TAPTWEAK, midstate_bytes(tag_engine("TapTweak")));
        assert_eq!(MIDSTATE_TAPSIGHASH, midstate_bytes(tag_engine("TapSighash")));

        // test that engine creation roundtrips
        assert_eq!(tag_engine("TapLeaf").midstate().unwrap(), <TapLeafTag as sha256t::Tag>::MIDSTATE);
        assert_eq!(tag_engine("TapBranch").midstate().unwrap(), <TapBranchTag as sha256t::Tag>::MIDSTATE);
        assert_eq!(tag_engine("TapTweak").midstate().unwrap(), <TapTweakTag as sha256t::Tag>::MIDSTATE);
        assert_eq!(tag_engine("TapSighash").midstate().unwrap(), <TapSighashTag as sha256t::Tag>::MIDSTATE);

        // check that hash creation is the same as building into the same engine
        fn empty_hash(tag_name: &str) -> [u8; 32] {
            let mut e = tag_engine(tag_name);
            e.input(&[]);
            sha256::Hash::from_engine(e).to_byte_array()
        }
        assert_eq!(
            empty_hash("TapLeaf"),
            sha256t::Hash::<TapLeafTag>::hash(&[]).to_byte_array()
        );
        assert_eq!(
            empty_hash("TapBranch"),
            sha256t::Hash::<TapBranchTag>::hash(&[]).to_byte_array()
        );
        assert_eq!(
            empty_hash("TapTweak"),
            sha256t::Hash::<TapTweakTag>::hash(&[]).to_byte_array()
        );
        assert_eq!(
            empty_hash("TapSighash"),
            sha256t::Hash::<TapSighashTag>::hash(&[]).to_byte_array()
        );
    }

    #[test]
    fn test_vectors_core() {
        //! Test vectors taken from Core

        // uninitialized writers
        //   CHashWriter writer = HasherTapLeaf;
        //   writer.GetSHA256().GetHex()
        assert_eq!(
            TapLeafHash::from_byte_array(
                sha256t::Hash::<TapLeafTag>::from_engine(TapLeafTag::engine()).to_byte_array()
            ).to_string(),
            "cbfa0621df37662ca57697e5847b6abaf92934a1a5624916f8d177a388c21252"
        );
        assert_eq!(
            TapBranchHash::from_byte_array(
                sha256t::Hash::<TapBranchTag>::from_engine(TapBranchTag::engine()).to_byte_array()
            ).to_string(),
            "dffd9fbe4c21c893fa934f8774eda0e1efdc06f52ffbf5c1533c6f4dec73c353"
        );
        assert_eq!(
            TapTweakHash::from_byte_array(
                sha256t::Hash::<TapTweakTag>::from_engine(TapTweakTag::engine()).to_byte_array()
            ).to_string(),
            "e4156b45ff9b277dd92a042af9eed8c91f1d037f68f0d6b20001ab749422a48a"
        );
        assert_eq!(
            TapSighashHash::from_byte_array(
                sha256t::Hash::<TapSighashTag>::from_engine(TapSighashTag::engine()).to_byte_array()
            ).to_string(),
            "03c8b9d47cdb5f7bf924e282ce99ba8d2fe581262a04002907d8bc4a9111bcda"
        );

        // 0-byte
        //   CHashWriter writer = HasherTapLeaf;
        //   writer << std::vector<unsigned char>{};
        //   writer.GetSHA256().GetHex()
        // Note that Core writes the 0 length prefix when an empty vector is written.
        assert_eq!(
            TapLeafHash::from_byte_array(sha256t::Hash::<TapLeafTag>::hash(&[0]).to_byte_array())
                .to_string(),
            "29589d5122ec666ab5b4695070b6debc63881a4f85d88d93ddc90078038213ed"
        );
        assert_eq!(
            TapBranchHash::from_byte_array(sha256t::Hash::<TapBranchTag>::hash(&[0]).to_byte_array())
                .to_string(),
            "1deb45569eb6b2da88b5c2ab46d6a64ab08d58a2fdd5f75a24e6c760194b5392"
        );
        assert_eq!(
            TapTweakHash::from_byte_array(sha256t::Hash::<TapTweakTag>::hash(&[0]).to_byte_array())
                .to_string(),
            "1eea90d42a359c89bbf702ddf6bde140349e95b9e8036ff1c37f04e6b53787cd"
        );
        assert_eq!(
            TapSighashHash::from_byte_array(
                sha256t::Hash::<TapSighashTag>::hash(&[0]).to_byte_array()
            ).to_string(),
            "cd10c023c300fb9a507dff136370fba1d8a0566667cfafc4099a8803e00dfdc2"
        );
    }
}
