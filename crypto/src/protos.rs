//
// Copyright (c) 2018 Stegos AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#![allow(bare_trait_objects)]

use failure::Error;
use stegos_serialization::traits::*;

use crate::bulletproofs::BulletProof;
use crate::hash::Hash;
use crate::pbc;
use crate::pbc::G1;
use crate::pbc::G2;
use crate::pbc::VRF;
use crate::scc::{EncryptedKey, Fr, Pt, PublicKey, SchnorrSig, SecretKey};
use ristretto_bulletproofs::RangeProof;

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

impl ProtoConvert for G1 {
    type Proto = crypto::G1;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = crypto::G1::new();
        proto.set_data(self.to_bytes().to_vec());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        Ok(G1::try_from_bytes(proto.get_data())?)
    }
}

impl ProtoConvert for G2 {
    type Proto = crypto::G2;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = crypto::G2::new();
        proto.set_data(self.to_bytes().to_vec());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        Ok(G2::try_from_bytes(proto.get_data())?)
    }
}

impl ProtoConvert for Hash {
    type Proto = crypto::Hash;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = crypto::Hash::new();
        proto.set_data(self.to_bytes().to_vec());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        Ok(Hash::try_from_bytes(proto.get_data())?)
    }
}

impl ProtoConvert for Fr {
    type Proto = crypto::Fr;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = crypto::Fr::new();
        proto.set_data(self.to_bytes().to_vec());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        Ok(Fr::try_from_bytes(proto.get_data())?)
    }
}

impl ProtoConvert for Pt {
    type Proto = crypto::Pt;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = crypto::Pt::new();
        proto.set_data(self.to_bytes().to_vec());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        Ok(Pt::try_from_bytes(proto.get_data())?)
    }
}

impl ProtoConvert for SecretKey {
    type Proto = crypto::SecretKey;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = crypto::SecretKey::new();
        proto.set_skeyf(Fr::from(*self).into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let fr: Fr = Fr::from_proto(proto.get_skeyf())?;
        Ok(SecretKey::from(fr))
    }
}

impl ProtoConvert for PublicKey {
    type Proto = crypto::PublicKey;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = crypto::PublicKey::new();
        let pt = Pt::from(*self);
        proto.set_point(pt.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let pt: Pt = Pt::from_proto(proto.get_point())?;
        Ok(PublicKey::from(pt))
    }
}

impl ProtoConvert for SchnorrSig {
    type Proto = crypto::SchnorrSig;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = crypto::SchnorrSig::new();
        proto.set_K(self.K.into_proto());
        proto.set_u(self.u.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let k: Pt = Pt::from_proto(proto.get_K())?;
        let u: Fr = Fr::from_proto(proto.get_u())?;
        Ok(SchnorrSig { K: k, u })
    }
}

impl ProtoConvert for pbc::PublicKey {
    type Proto = crypto::SecurePublicKey;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = crypto::SecurePublicKey::new();
        let g: G2 = G2::from(*self);
        proto.set_point(g.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let g: G2 = G2::from_proto(proto.get_point())?;
        Ok(pbc::PublicKey::from(g))
    }
}

impl ProtoConvert for pbc::Signature {
    type Proto = crypto::SecureSignature;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = crypto::SecureSignature::new();
        let g: G1 = G1::from(*self);
        proto.set_point(g.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let g: G1 = G1::from_proto(proto.get_point())?;
        Ok(pbc::Signature::from(g))
    }
}

impl ProtoConvert for EncryptedKey {
    type Proto = crypto::EncryptedKey;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = crypto::EncryptedKey::new();
        let mut payload_proto = crypto::EncryptedKey_Payload::new();
        payload_proto.set_ag(self.ag.into_proto());
        payload_proto.set_ctxt(self.payload.clone());
        proto.set_payload(payload_proto);
        proto.set_sig(self.sig.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let payload_proto = proto.get_payload();
        let ag = Pt::from_proto(payload_proto.get_ag())?;
        let payload = payload_proto.get_ctxt().to_vec();
        let sig = SchnorrSig::from_proto(proto.get_sig())?;
        Ok(EncryptedKey { ag, payload, sig })
    }
}

impl ProtoConvert for BulletProof {
    type Proto = crypto::BulletProof;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = crypto::BulletProof::new();
        proto.set_vcmt(self.vcmt.into_proto());
        proto.set_proof(self.proof.to_bytes());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let vcmt = Pt::from_proto(proto.get_vcmt())?;
        let proof = RangeProof::from_bytes(proto.get_proof())?;
        Ok(BulletProof { vcmt, proof })
    }
}

impl ProtoConvert for VRF {
    type Proto = crypto::VRF;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = crypto::VRF::new();
        proto.set_rand(self.rand.into_proto());
        proto.set_proof(self.proof.into_proto());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        let rand = Hash::from_proto(proto.get_rand())?;
        let proof = G1::from_proto(proto.get_proof())?;
        Ok(VRF { rand, proof })
    }
}

#[cfg(feature = "flint")]
impl ProtoConvert for crate::dicemix::ParticipantID {
    type Proto = crypto::DiceMixParticipantID;
    fn into_proto(&self) -> Self::Proto {
        let mut proto = crypto::DiceMixParticipantID::new();
        proto.set_pkey(self.pkey.into_proto());
        proto.set_seed(self.seed.to_vec());
        proto
    }
    fn from_proto(proto: &Self::Proto) -> Result<Self, Error> {
        use crate::CryptoError;
        let pkey = pbc::PublicKey::from_proto(proto.get_pkey())?;
        let seed_slice = proto.get_seed();
        if seed_slice.len() != 32 {
            return Err(CryptoError::InvalidBinaryLength(32, seed_slice.len()).into());
        }
        let mut seed: [u8; 32] = [0u8; 32];
        seed.copy_from_slice(seed_slice);
        Ok(crate::dicemix::ParticipantID { pkey, seed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bulletproofs::make_range_proof;
    use crate::hash::Hashable;
    use crate::pbc;
    use crate::scc::{decrypt_key, encrypt_key, make_random_keys};
    use rand::rngs::ThreadRng;
    use rand::thread_rng;
    use rand::Rng;

    fn roundtrip<T>(x: &T) -> T
    where
        T: ProtoConvert + Hashable + std::fmt::Debug,
    {
        let r = T::from_proto(&x.into_proto()).unwrap();
        assert_eq!(Hash::digest(x), Hash::digest(&r));
        r
    }

    #[test]
    fn points() {
        let pt: Pt = Pt::random();
        roundtrip(&pt);

        let fr = Fr::random();
        roundtrip(&fr);

        let g1 = G1::generator();
        roundtrip(&g1);

        let g2 = G2::generator();
        roundtrip(&g2);
    }

    #[test]
    fn keys() {
        let (_skey, pkey) = make_random_keys();
        roundtrip(&pkey);
    }

    #[test]
    fn secure_keys() {
        let (_skey, pkey) = pbc::make_random_keys();
        roundtrip(&pkey);
    }

    #[test]
    fn hash() {
        let mut rng: ThreadRng = thread_rng();
        let hash = Hash::try_from_bytes(&rng.gen::<[u8; 32]>()).unwrap();
        roundtrip(&hash);
    }

    #[test]
    fn bulletproofs() {
        let (bp, gamma) = make_range_proof(100);
        roundtrip(&bp);
        roundtrip(&gamma);
    }

    #[test]
    fn encrypted_secret_key() {
        let passphrase = "test";
        let key_to_encrypt = b"key";
        let encr_key = encrypt_key(&passphrase, key_to_encrypt);
        roundtrip(&encr_key);
        let key_to_encrypt2 = decrypt_key(&passphrase, &encr_key).expect("valid");
        assert_eq!(key_to_encrypt.to_vec(), key_to_encrypt2);
    }

    #[test]
    fn aont_secret_key() {
        // test AONT serialization of SecretKey
        let (skey, _pkey) = make_random_keys();
        roundtrip(&skey);
    }
}
