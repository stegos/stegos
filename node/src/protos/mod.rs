//! Protobuf Definitions.

//
// Copyright (c) 2018 Stegos
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

pub mod node;

use failure::Error;
use stegos_blockchain::{Output, Transaction, TransactionBody};
use stegos_crypto::bulletproofs::{BulletProof, DotProof, L2_NBASIS, LR};
use stegos_crypto::curve1174::cpt::Pt;
use stegos_crypto::curve1174::cpt::{EncryptedPayload, PublicKey, SchnorrSig};
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::Hash;
use stegos_crypto::CryptoError;

pub trait IntoProto<T: ::protobuf::Message> {
    fn into_proto(&self) -> T;
}

pub trait FromProto<T: ::protobuf::Message>: Sized {
    fn from_proto(proto: &T) -> Result<Self, Error>;
}

//
// Pt
//

impl IntoProto<node::Pt> for Pt {
    fn into_proto(&self) -> node::Pt {
        let mut proto = node::Pt::new();
        proto.set_data(self.into_bytes().to_vec());
        proto
    }
}

impl FromProto<node::Pt> for Pt {
    fn from_proto(proto: &node::Pt) -> Result<Self, Error> {
        Ok(Pt::try_from_bytes(proto.get_data())?)
    }
}

//
// Fr
//

impl IntoProto<node::Fr> for Fr {
    fn into_proto(&self) -> node::Fr {
        let mut proto = node::Fr::new();
        proto.set_data(self.into_bytes().to_vec());
        proto
    }
}

impl FromProto<node::Fr> for Fr {
    fn from_proto(proto: &node::Fr) -> Result<Self, Error> {
        Ok(Fr::try_from_bytes(proto.get_data())?)
    }
}

//
// Hash
//

impl IntoProto<node::Hash> for Hash {
    fn into_proto(&self) -> node::Hash {
        let mut proto = node::Hash::new();
        proto.set_data(self.into_bytes().to_vec());
        proto
    }
}

impl FromProto<node::Hash> for Hash {
    fn from_proto(proto: &node::Hash) -> Result<Self, Error> {
        Ok(Hash::try_from_bytes(proto.get_data())?)
    }
}

//
// Public Key
//

impl IntoProto<node::PublicKey> for PublicKey {
    fn into_proto(&self) -> node::PublicKey {
        let mut proto = node::PublicKey::new();
        let pt: Pt = (*self).into();
        proto.set_point(pt.into_proto());
        proto
    }
}

impl FromProto<node::PublicKey> for PublicKey {
    fn from_proto(proto: &node::PublicKey) -> Result<Self, Error> {
        let pt: Pt = Pt::from_proto(proto.get_point())?;
        Ok(PublicKey::from(pt))
    }
}

//
// SchnorrSig
//

impl IntoProto<node::SchnorrSig> for SchnorrSig {
    fn into_proto(&self) -> node::SchnorrSig {
        let mut proto = node::SchnorrSig::new();
        proto.set_K(self.K.into_proto());
        proto.set_u(self.u.into_proto());
        proto
    }
}

#[allow(non_snake_case)]
impl FromProto<node::SchnorrSig> for SchnorrSig {
    fn from_proto(proto: &node::SchnorrSig) -> Result<Self, Error> {
        let K: Pt = Pt::from_proto(proto.get_K())?;
        let u: Fr = Fr::from_proto(proto.get_u())?;
        Ok(SchnorrSig { K, u })
    }
}

//
// EncryptedPayload
//

impl IntoProto<node::EncryptedPayload> for EncryptedPayload {
    fn into_proto(&self) -> node::EncryptedPayload {
        let mut proto = node::EncryptedPayload::new();
        proto.set_apkg(self.apkg.into_proto());
        proto.set_ag(self.ag.into_proto());
        proto.set_ctxt(self.ctxt.clone());
        proto
    }
}

impl FromProto<node::EncryptedPayload> for EncryptedPayload {
    fn from_proto(proto: &node::EncryptedPayload) -> Result<Self, Error> {
        let apkg = Pt::from_proto(proto.get_apkg())?;
        let ag = Pt::from_proto(proto.get_ag())?;
        let ctxt = proto.get_ctxt().to_vec();
        Ok(EncryptedPayload { apkg, ag, ctxt })
    }
}

//
// BulletProof
//

impl IntoProto<node::LR> for LR {
    fn into_proto(&self) -> node::LR {
        let mut proto = node::LR::new();
        proto.set_x(self.x.into_proto());
        proto.set_l(self.l.into_proto());
        proto.set_r(self.r.into_proto());
        proto
    }
}

impl FromProto<node::LR> for LR {
    fn from_proto(proto: &node::LR) -> Result<Self, Error> {
        let x = Fr::from_proto(proto.get_x())?;
        let l = Pt::from_proto(proto.get_l())?;
        let r = Pt::from_proto(proto.get_r())?;
        Ok(LR { x, l, r })
    }
}

impl IntoProto<node::DotProof> for DotProof {
    fn into_proto(&self) -> node::DotProof {
        let mut proto = node::DotProof::new();
        proto.set_u(self.u.into_proto());
        proto.set_pcmt(self.pcmt.into_proto());
        proto.set_a(self.a.into_proto());
        proto.set_b(self.b.into_proto());
        for lr in self.xlrs.iter() {
            proto.xlrs.push(lr.into_proto());
        }
        proto
    }
}

impl FromProto<node::DotProof> for DotProof {
    fn from_proto(proto: &node::DotProof) -> Result<Self, Error> {
        let u = Pt::from_proto(proto.get_u())?;
        let pcmt = Pt::from_proto(proto.get_pcmt())?;
        let a = Fr::from_proto(proto.get_a())?;
        let b = Fr::from_proto(proto.get_b())?;
        let xlrs1 = proto.get_xlrs();
        if xlrs1.len() != L2_NBASIS {
            return Err(CryptoError::InvalidBinaryLength(L2_NBASIS, xlrs1.len()).into());
        }

        let zero = LR::from_proto(&xlrs1[0])?;
        let mut xlrs: [LR; L2_NBASIS] = [zero; L2_NBASIS];
        for (i, lr) in xlrs1.iter().enumerate() {
            xlrs[i] = LR::from_proto(lr)?;
        }

        Ok(DotProof {
            u,
            pcmt,
            a,
            b,
            xlrs,
        })
    }
}

impl IntoProto<node::BulletProof> for BulletProof {
    fn into_proto(&self) -> node::BulletProof {
        let mut proto = node::BulletProof::new();
        proto.set_vcmt(self.vcmt.into_proto());
        proto.set_acmt(self.acmt.into_proto());
        proto.set_scmt(self.scmt.into_proto());
        proto.set_t1_cmt(self.t1_cmt.into_proto());
        proto.set_t2_cmt(self.t2_cmt.into_proto());
        proto.set_tau_x(self.tau_x.into_proto());
        proto.set_mu(self.mu.into_proto());
        proto.set_t_hat(self.t_hat.into_proto());
        proto.set_dot_proof(self.dot_proof.into_proto());
        proto.set_x(self.x.into_proto());
        proto.set_y(self.y.into_proto());
        proto.set_z(self.z.into_proto());
        proto
    }
}

impl FromProto<node::BulletProof> for BulletProof {
    fn from_proto(proto: &node::BulletProof) -> Result<Self, Error> {
        let vcmt = Pt::from_proto(proto.get_vcmt())?;
        let acmt = Pt::from_proto(proto.get_acmt())?;
        let scmt = Pt::from_proto(proto.get_scmt())?;
        let t1_cmt = Pt::from_proto(proto.get_t1_cmt())?;
        let t2_cmt = Pt::from_proto(proto.get_t2_cmt())?;
        let tau_x = Fr::from_proto(proto.get_tau_x())?;
        let mu = Fr::from_proto(proto.get_mu())?;
        let t_hat = Fr::from_proto(proto.get_t_hat())?;
        let dot_proof = DotProof::from_proto(proto.get_dot_proof())?;
        let x = Fr::from_proto(proto.get_x())?;
        let y = Fr::from_proto(proto.get_y())?;
        let z = Fr::from_proto(proto.get_z())?;
        Ok(BulletProof {
            vcmt,
            acmt,
            scmt,
            t1_cmt,
            t2_cmt,
            tau_x,
            mu,
            t_hat,
            dot_proof,
            x,
            y,
            z,
        })
    }
}

impl IntoProto<node::Output> for Output {
    fn into_proto(&self) -> node::Output {
        let mut proto = node::Output::new();
        proto.set_recipient(self.recipient.into_proto());
        proto.set_proof(self.proof.into_proto());
        proto.set_payload(self.payload.into_proto());
        proto
    }
}

impl FromProto<node::Output> for Output {
    fn from_proto(proto: &node::Output) -> Result<Self, Error> {
        let recipient = PublicKey::from_proto(proto.get_recipient())?;
        let proof = BulletProof::from_proto(proto.get_proof())?;
        let payload = EncryptedPayload::from_proto(proto.get_payload())?;
        Ok(Output {
            recipient,
            proof,
            payload,
        })
    }
}

impl IntoProto<node::Transaction> for Transaction {
    fn into_proto(&self) -> node::Transaction {
        let mut proto = node::Transaction::new();

        for txin in &self.body.txins {
            proto.txins.push(txin.into_proto());
        }
        for txout in &self.body.txouts {
            proto.txouts.push(txout.into_proto());
        }
        proto.set_gamma(self.body.gamma.into_proto());
        proto.set_fee(self.body.fee);
        proto.set_sig(self.sig.into_proto());
        proto
    }
}

impl FromProto<node::Transaction> for Transaction {
    fn from_proto(proto: &node::Transaction) -> Result<Self, Error> {
        let mut txins = Vec::<Hash>::with_capacity(proto.txins.len());
        for txin in proto.txins.iter() {
            txins.push(Hash::from_proto(txin)?);
        }
        let mut txouts = Vec::<Output>::with_capacity(proto.txouts.len());
        for txout in proto.txouts.iter() {
            txouts.push(Output::from_proto(txout)?);
        }
        let gamma = Fr::from_proto(proto.get_gamma())?;
        let fee = proto.get_fee();
        let sig = SchnorrSig::from_proto(proto.get_sig())?;

        Ok(Transaction {
            body: TransactionBody {
                txins,
                txouts,
                gamma,
                fee,
            },
            sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rand::rngs::ThreadRng;
    use rand::thread_rng;
    use rand::Rng;
    use stegos_crypto::bulletproofs::make_range_proof;
    use stegos_crypto::curve1174::cpt::make_random_keys;
    use stegos_crypto::curve1174::ecpt::ECp;
    use stegos_crypto::hash::Hashable;

    fn roundtrip<M, T>(x: &T) -> T
    where
        M: ::protobuf::Message,
        T: IntoProto<M> + FromProto<M> + Hashable + std::fmt::Debug,
    {
        let r = T::from_proto(&x.clone().into_proto()).unwrap();
        assert_eq!(Hash::digest(x), Hash::digest(&r));
        r
    }

    #[test]
    fn points() {
        let pt: Pt = Pt::from(ECp::random());
        roundtrip(&pt);

        let fr = Fr::random();
        roundtrip(&fr);
    }

    #[test]
    fn keys() {
        let (_skey, pkey, sig) = make_random_keys();
        roundtrip(&pkey);
        roundtrip(&sig);
    }

    #[test]
    fn hash() {
        let mut rng: ThreadRng = thread_rng();
        let hash = Hash::try_from_bytes(&rng.gen::<[u8; 32]>()).unwrap();
        roundtrip(&hash);
    }

    #[test]
    fn bulletproofs() {
        let lr = LR {
            x: Fr::random(),
            l: Pt::from(ECp::random()),
            r: Pt::from(ECp::random()),
        };
        roundtrip(&lr);

        let dp = DotProof {
            u: Pt::random(),
            pcmt: Pt::random(),
            a: Fr::random(),
            b: Fr::random(),
            xlrs: [lr, lr, lr, lr, lr, lr],
        };

        roundtrip(&dp);

        let (bp, gamma) = make_range_proof(100);
        roundtrip(&bp);
        roundtrip(&gamma);
    }

    #[test]
    fn transactions() {
        let (skey0, _pkey0, _sig0) = make_random_keys();
        let (skey1, pkey1, _sig1) = make_random_keys();
        let (_skey2, pkey2, _sig2) = make_random_keys();

        let timestamp = Utc::now().timestamp() as u64;
        let amount: i64 = 1_000_000;
        let fee: i64 = 0;

        // "genesis" output by 0
        let (output0, _delta0) =
            Output::new(timestamp, &skey0, &pkey1, amount).expect("keys are valid");

        // Transaction from 1 to 2
        let inputs1 = [output0];
        let (output1, delta1) =
            Output::new(timestamp, &skey1, &pkey2, amount).expect("keys are valid");

        roundtrip(&output1);
        roundtrip(&delta1);

        let tx =
            Transaction::new(&skey1, &inputs1, &[output1], delta1, fee).expect("keys are valid");
        tx.validate(&inputs1).unwrap();

        let tx2 = roundtrip(&tx);
        tx2.validate(&inputs1).unwrap();
    }
}
