//
// Copyright (c) 2019 Stegos AG
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

use ff::*;
use old_rand::*;
use paired::*;
use std::collections::HashSet;
use std::ops::AddAssign;

fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut ans = Vec::<u8>::new();
    ans.extend_from_slice(a);
    ans.extend_from_slice(b);
    ans
}

const HASH_KEY: &[u8] = b"BLSSignatureSeed";

macro_rules! impl_copy {
        ($name: ident) => {
            impl<E: Engine> Copy for $name<E> {
            }
            impl<E: Engine> Clone for $name<E> {
                fn clone(&self) -> Self {
                    *self
                }
            }
        };
        ($($name: ident),+) => {
            $(impl_copy!{$name})+
        }
    }

// -----------------------------------------------------------
// Internal decompressed (projective) versions

#[derive(Eq, PartialEq, Debug)]
pub struct ISignature<E: Engine> {
    pub s: E::G1,
}

#[derive(Eq, PartialEq, Debug)]
pub struct ISecretKey<E: Engine> {
    pub x: E::Fr,
}

#[derive(Eq, PartialEq, Debug)]
pub struct IPublicKey<E: Engine> {
    pub p_pub: E::G2,
}

#[derive(Eq, PartialEq, Debug)]
pub struct ISecretSubKey<E: Engine> {
    pub pt: E::G1,
}

#[derive(Eq, PartialEq, Debug)]
pub struct IPublicSubKey<E: Engine> {
    pub pt: E::G2,
}

#[derive(Eq, PartialEq, Debug)]
pub struct IG1<E: Engine> {
    pub pt: E::G1Affine,
}

#[derive(Eq, PartialEq, Debug)]
pub struct IG2<E: Engine> {
    pub pt: E::G2Affine,
}

impl_copy! {ISignature, ISecretKey, IPublicKey, ISecretSubKey, IPublicSubKey, IG1, IG2}

// ---------------------------------------------------------------------

impl<E: Engine> IG1<E> {
    pub fn zero() -> Self {
        IG1 {
            pt: E::G1Affine::zero(),
        }
    }

    pub fn generator() -> Self {
        IG1 {
            pt: E::G1Affine::one(),
        }
    }

    pub fn pair_with(&self, other: E::G2Affine) -> E::Fqk {
        E::pairing(self.pt, other)
    }

    pub fn sakke_fqk(fr: E::Fr) -> E::Fqk {
        E::pairing(E::G1Affine::one().mul(fr), E::G2Affine::one())
    }
}

impl<E: Engine> AddAssign<IG1<E>> for IG1<E> {
    fn add_assign(&mut self, other: Self) {
        let mut tmp = self.pt.into_projective();
        tmp.add_assign(&other.pt.into_projective());
        self.pt = tmp.into_affine();
    }
}

impl<E: Engine> IG2<E> {
    pub fn zero() -> Self {
        IG2 {
            pt: E::G2Affine::zero(),
        }
    }

    pub fn generator() -> Self {
        IG2 {
            pt: E::G2Affine::one(),
        }
    }
}

impl<E: Engine> AddAssign<IG2<E>> for IG2<E> {
    fn add_assign(&mut self, other: Self) {
        let mut tmp = self.pt.into_projective();
        tmp.add_assign(&other.pt.into_projective());
        self.pt = tmp.into_affine();
    }
}

impl<E: Engine> ISecretKey<E> {
    pub fn generate<R: Rng>(csprng: &mut R) -> Self {
        ISecretKey {
            x: E::Fr::rand(csprng),
        }
    }

    pub fn cloaked_pair(&self) -> (E::Fr, E::Fr) {
        let mut cloak = E::Fr::rand(&mut thread_rng());
        let mut tmp1 = self.x;
        tmp1.add_assign(&cloak);
        cloak.negate();
        (tmp1, cloak)
    }

    pub fn sign(&self, message: &[u8]) -> ISignature<E> {
        let cmsg = concat(HASH_KEY, message);
        let mut hpt = E::G1::hash(&cmsg);
        let mut hptc = hpt;
        let (cskey, cloak) = self.cloaked_pair();
        hptc.mul_assign(cloak);
        hpt.mul_assign(cskey);
        hpt.add_assign(&hptc);
        ISignature { s: hpt }
    }

    pub fn into_subkey(&self, id: E::Fr) -> ISecretSubKey<E> {
        let mut tmp = id;
        tmp.add_assign(&self.x);
        let itmp = tmp.inverse().unwrap();
        let pt = E::G1Affine::one().mul(itmp);
        ISecretSubKey { pt }
    }

    pub fn into_vrf(&self, id: E::Fr) -> (ISecretSubKey<E>, E::Fqk) {
        let proof = self.into_subkey(id);
        let rand = E::pairing(proof.pt, E::G2Affine::one());
        (proof, rand)
    }
}

impl<E: Engine> ISecretSubKey<E> {
    pub fn into_fq12(&self) -> E::Fqk {
        E::pairing(self.pt, E::G2Affine::one())
    }

    pub fn check_vrf(&self, pskey: &IPublicSubKey<E>) -> bool {
        let lhs = E::pairing(self.pt, pskey.pt);
        let rhs = E::pairing(E::G1::one(), E::G2Affine::one());
        lhs == rhs
    }
}

impl<E: Engine> IPublicKey<E> {
    pub fn from_secret(secret: &ISecretKey<E>) -> Self {
        let mut tmp1 = E::G2Affine::one().into_projective();
        let mut tmp2 = tmp1;
        let (cskey, cloak) = secret.cloaked_pair();
        tmp1.mul_assign(cskey);
        tmp2.mul_assign(cloak);
        tmp1.add_assign(&tmp2);
        IPublicKey { p_pub: tmp1 }
    }

    pub fn verify(&self, message: &[u8], signature: &ISignature<E>) -> bool {
        let cmsg = concat(HASH_KEY, message);
        let h = E::G1::hash(&cmsg);
        let lhs = E::pairing(signature.s, E::G2Affine::one());
        let rhs = E::pairing(h, self.p_pub);
        lhs == rhs
    }

    pub fn into_subkey(&self, id: E::Fr) -> IPublicSubKey<E> {
        let mut pt = E::G2Affine::one().mul(id);
        pt.add_assign(&self.p_pub);
        IPublicSubKey { pt }
    }
}

impl<E: Engine> ISignature<E> {
    pub fn is_zero(&self) -> bool {
        self.s.is_zero()
    }
}

impl<E: Engine> AddAssign<ISignature<E>> for ISignature<E> {
    fn add_assign(&mut self, other: ISignature<E>) {
        self.s.add_assign(&other.s)
    }
}

#[derive(Copy, Clone)]
pub struct IKeypair<E: Engine> {
    pub secret: ISecretKey<E>,
    pub public: IPublicKey<E>,
}

impl<E: Engine> IKeypair<E> {
    pub fn generate<R: Rng>(csprng: &mut R) -> Self {
        let secret = ISecretKey::generate(csprng);
        let public = IPublicKey::from_secret(&secret);
        IKeypair { secret, public }
    }

    pub fn sign(&self, message: &[u8]) -> ISignature<E> {
        self.secret.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &ISignature<E>) -> bool {
        self.public.verify(message, signature)
    }
}

#[derive(Copy, Clone)]
pub struct IAggregateSignature<E: Engine>(ISignature<E>);

impl<E: Engine> IAggregateSignature<E> {
    pub fn new() -> Self {
        IAggregateSignature(ISignature { s: E::G1::zero() })
    }

    pub fn from_signatures(sigs: &Vec<ISignature<E>>) -> Self {
        let mut s = Self::new();
        for sig in sigs {
            s.aggregate(sig);
        }
        s
    }

    pub fn aggregate(&mut self, sig: &ISignature<E>) {
        self.0.s.add_assign(&sig.s);
    }

    pub fn verify(&self, inputs: &Vec<(&IPublicKey<E>, &[u8])>) -> bool {
        // Messages must be distinct
        let messages: HashSet<&[u8]> = inputs.iter().map(|&(_, m)| m).collect();
        if messages.len() != inputs.len() {
            return false;
        }
        // Check pairings
        let lhs = E::pairing(self.0.s, E::G2Affine::one());
        let mut rhs = E::Fqk::one();
        for input in inputs {
            let cmsg = concat(HASH_KEY, input.1);
            let h = E::G1::hash(&cmsg);
            rhs.mul_assign(&E::pairing(h, input.0.p_pub));
        }
        lhs == rhs
    }
}
