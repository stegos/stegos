
use super::*;

// -----------------------------------------------------------------
// Fq is the field in which the curve is computed - coords are all elements of Fq
// In Elliptic curve point operations these coordinates are converted to Fq51 representation
//
// Type Fq is for working directly in the field Fq, using fast Montgomery reduction
// for modular multiply. As such, Fq is scaled by the Q_ONE value. Coordinate values
// Fq51 must come from unscaled Fq values, and for that we have FqUnscaled types to 
// help avoid the overhead of scaling / de-scaling. 

pub struct FqUnscaled(pub U256);

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct Fq(U256);

pub const Q : U256 = U256([0xFFFFFFFFFFFFFFF7, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFF]); // |Fq|

const ZQ_SQUARED : Fq = Fq(U256([0x014400, 0x00, 0x00, 0x00])); // (2^256)^2 mod |Fq|
const FQINV : u64 = 0x8E38E38E38E38E39; // (-1/|Fq|) mod 2^64
const Q_ONE : Fq = Fq(U256([0x0120, 0x00, 0x00, 0x00])); // = 2^256 mod |Fq|
const ZQ_CUBED : Fq = Fq(U256([0x016C8000, 0x00, 0x00, 0x00])); // = (2^256)^3 mod |Fq|

impl PartialOrd for Fq {
    fn partial_cmp(&self, other: &Fq) -> Option<Ordering> {
        U256::partial_cmp(&self.0, &other.0)
    }
}

impl Ord for Fq {
    fn cmp(&self, other: &Fq) -> Ordering {
        U256::cmp(&self.0, &other.0)
    }
}

impl Fq {
    pub fn zero() -> Fq {
        Fq(U256::zero())
    }

    pub fn one() -> Fq {
        Q_ONE
    }

    pub fn invert(self) -> Fq {
        let mut tmp = self;
        U256::invert_mod(&mut tmp.0, &Q);
        ZQ_CUBED * tmp
    }
}

impl fmt::Display for Fq {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let FqUnscaled(tmp) = FqUnscaled::from(*self);
        write!(f, "Fq({})", tmp.nbr_str())
    }
}

impl From<i64> for FqUnscaled {
    fn from(x : i64) -> FqUnscaled {
        if x >= 0 {
            let z = U256([x as u64, 0, 0, 0]);
            FqUnscaled(z)
        } else {
            let tmp = [(-x) as u64, 0, 0, 0];
            let mut tmp2 = Q.0;
            sub_noborrow(&mut tmp2, &tmp);
            let z = U256(tmp2);
            FqUnscaled(z)
        }
    }
}

impl From<FqUnscaled> for Fq {
    fn from(x : FqUnscaled) -> Fq {
        let FqUnscaled(z) = x;
        ZQ_SQUARED * Fq(z)
    }
}

impl From<i64> for Fq {
    fn from(x : i64) -> Fq {
        Fq::from(FqUnscaled::from(x))
    }
}

impl Add<Fq> for Fq {
    type Output = Fq;
    fn add(self, other: Fq) -> Fq {
        let mut tmp = self;
        U256::add_mod(&mut tmp.0, &other.0, &Q);
        tmp
    }
}

impl Add<i64> for Fq {
    type Output = Fq;
    fn add(self, other: i64) -> Fq {
        self + Fq::from(other)
    }
}

impl Add<Fq> for i64 {
    type Output = Fq;
    fn add(self, other: Fq) -> Fq {
        Fq::from(self) + other
    }
}

impl Sub<Fq> for Fq {
    type Output = Fq;
    fn sub(self, other: Fq) -> Fq {
        let mut tmp = self;
        U256::sub_mod(&mut tmp.0, &other.0, &Q);
        tmp
    }
}

impl Sub<i64> for Fq {
    type Output = Fq;
    fn sub(self, other: i64) -> Fq {
        self - Fq::from(other)
    }
}

impl Sub<Fq> for i64 {
    type Output = Fq;
    fn sub(self, other: Fq) -> Fq {
        Fq::from(self) - other
    }
}

impl Neg for Fq {
    type Output = Fq;
    fn neg(self) -> Fq {
        let mut tmp = self;
        U256::neg_mod(&mut tmp.0, &Q);
        tmp
    }
}

impl Mul<Fq> for Fq {
    type Output = Fq;
    fn mul(self, other: Fq) -> Fq {
        let mut tmp = self;
        U256::mul_mod(&mut tmp.0, &other.0, &Q, FQINV);
        tmp
    }
}

impl Mul<i64> for Fq {
    type Output = Fq;
    fn mul(self, other: i64) -> Fq {
        self * Fq::from(other)
    }
}

impl Mul<Fq> for i64 {
    type Output = Fq;
    fn mul(self, other: Fq) -> Fq {
        other * self
    }
}

impl Div<Fq> for Fq {
    type Output = Fq;
    fn div(self, other: Fq) -> Fq {
        self * Fq::invert(other)
    }
}

impl Div<i64> for Fq {
    type Output = Fq;
    fn div(self, other: i64) -> Fq {
        self / Fq::from(other)
    }
}

impl Div<Fq> for i64 {
    type Output = Fq;
    fn div(self, other: Fq) -> Fq {
        if self == 1 {
            Fq::invert(other)
        } else {
            Fq::from(self) / other
        }
    }
}

impl From<FqUnscaled> for U256 {
    fn from(x: FqUnscaled) -> U256 {
        x.0
    }
}

impl From<Fq> for FqUnscaled {
    fn from(x: Fq) -> FqUnscaled {
        let mut tmp = x.0;
        mul_collapse(&mut tmp.0, &Q.0, FQINV);
        FqUnscaled(tmp)
    }
}

pub fn str_to_Fq(s: &str) -> Fq {
    let mut bin : [u64;4] = [0;4];
    str_to_bin64(s, &mut bin);
    let mut ans = U256(bin);
    while ans >= Q {
        sub_noborrow(&mut ans.0, &Q.0);
    }
    Fq::from(FqUnscaled(ans))
}

