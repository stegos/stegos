// --------------------------------------------------------------------------
// Faster, but less secure, pairings with curves AR160 (type A, r approx 160 bits)
// (intended for eRandHound ephemeral secrets)

use super::*;

#[derive(Copy, Clone)]
pub struct Zr([u8;ZR_SIZE_AR160]);

impl Zr {
    pub fn new() -> Zr {
        Zr(Zr::wv())
    }
    
    fn wv() -> [u8; ZR_SIZE_AR160] {
        // wv = Working Vector
        [0u8;ZR_SIZE_AR160]
    }

    pub fn random() -> Zr {
        Zr(random::<[u8;ZR_SIZE_AR160]>())
    }

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn from_str(s : &str) -> Zr {
        let mut v = Zr::wv();
        hexstr_to_u8v(&s, &mut v);
        Zr(v)
    }

    pub fn from_int(a : i64) -> Zr {
        let mut v = Zr::wv(); // big-endian encoding as byte vector
        let mut va = if a < 0 { -(a as i128) } else { a as i128 };
        for ix in 0 .. 8 {
            v[ZR_SIZE_AR160-ix-1] = (va & 0x0ff) as u8;
            va >>= 8;
        }
        if a < 0 { -Zr(v) } else { Zr(v) }
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("Zr", &self.base_vector())
    }
}

impl From<i64> for Zr {
    fn from(x : i64) -> Zr {
        Zr::from_int(x)
    }
}

impl fmt::Display for Zr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

// -------------------------------------
// Zr op i64

impl Add<i64> for Zr {
    type Output = Zr;
    fn add(self, other: i64) -> Zr {
        self + Zr::from(other)
    }
}

impl Sub<i64> for Zr {
    type Output = Zr;
    fn sub(self, other: i64) -> Zr {
        self - Zr::from(other)
    }
}

impl Mul<i64> for Zr {
    type Output = Zr;
    fn mul(self, other: i64) -> Zr {
        self * Zr::from(other)
    }
}

impl Div<i64> for Zr {
    type Output = Zr;
    fn div(self, other: i64) -> Zr {
        self / Zr::from(other)
    }
}

// -------------------------------------
// i64 op Zr
impl Add<Zr> for i64 {
    type Output = Zr;
    fn add(self, other: Zr) -> Zr {
        Zr::from(self) + other
    }
}

impl Sub<Zr> for i64 {
    type Output = Zr;
    fn sub(self, other: Zr) -> Zr {
        Zr::from(self) - other
    }
}

impl Mul<Zr> for i64 {
    type Output = Zr;
    fn mul(self, other: Zr) -> Zr {
        Zr::from(self) * other
    }
}

impl Div<Zr> for i64 {
    type Output = Zr;
    fn div(self, other: Zr) -> Zr {
        Zr::from(self) / other
    }
}

// -------------------------------------
// Zr op Zr

impl Neg for Zr {
    type Output = Zr;
    fn neg(self) -> Zr {
        neg_Zr(&self)
    }
}

impl Add<Zr> for Zr {
    type Output = Zr;
    fn add(self, other: Zr) -> Zr {
        add_Zr_Zr(&self, &other)
    }
}

impl Sub<Zr> for Zr {
    type Output = Zr;
    fn sub(self, other: Zr) -> Zr {
        sub_Zr_Zr(&self, &other)
    }
}

impl Mul<Zr> for Zr {
    type Output = Zr;
    fn mul(self, other: Zr) -> Zr {
        mul_Zr_Zr(&self, &other)
    }
}

impl Div<Zr> for Zr {
    type Output = Zr;
    fn div(self, other: Zr) -> Zr {
        div_Zr_Zr(&self, &other)
    }
}

impl AddAssign<i64> for Zr {
    fn add_assign(&mut self, other: i64) {
        *self += Zr::from(other);
    }
}

  impl SubAssign<i64> for Zr {
    fn sub_assign(&mut self, other: i64) {
        *self -= Zr::from(other);
    }
}

impl MulAssign<i64> for Zr {
    fn mul_assign(&mut self, other: i64) {
        *self *= Zr::from(other);
    }
}

  impl DivAssign<i64> for Zr {
    fn div_assign(&mut self, other: i64) {
        *self /= Zr::from(other);
    }  
}

impl AddAssign<Zr> for Zr {
    fn add_assign(&mut self, other: Zr) {
        *self = *self + other;
    }
}

  impl SubAssign<Zr> for Zr {
    fn sub_assign(&mut self, other: Zr) {
        *self = *self - other;
    }
}

impl MulAssign<Zr> for Zr {
    fn mul_assign(&mut self, other: Zr) {
        *self = *self * other;
    }   
}

  impl DivAssign<Zr> for Zr {
    fn div_assign(&mut self, other: Zr) {
        *self = *self / other;
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
pub struct G1([u8;G1_SIZE_AR160]);

impl G1 {
    pub fn new() -> G1 {
        G1(G1::wv())
    }
    
    fn wv() -> [u8; G1_SIZE_AR160] {
        [0u8;G1_SIZE_AR160]
    }

    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("G1", &self.base_vector())
    }

    pub fn from_str(s : &str) -> G1 {
        let mut v = G1::wv();
        hexstr_to_u8v(&s, &mut v);
        G1(v)
    }
}

impl fmt::Display for G1 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Neg for G1 {
    type Output = G1;
    fn neg(self) -> G1 {
        neg_G1(&self)
    }
}

impl Add<G1> for G1 {
    type Output = G1;
    fn add(self, other: G1) -> G1 {
        add_G1_G1(&self, &other)
    }
}

impl Sub<G1> for G1 {
    type Output = G1;
    fn sub(self, other: G1) -> G1 {
        sub_G1_G1(&self, &other)
    }
}

impl Mul<Zr> for G1 {
    type Output = G1;
    fn mul(self, other: Zr) -> G1 {
        mul_G1_Zr(&self, &other)
    }
}

impl Div<Zr> for G1 {
    type Output = G1;
    fn div(self, other: Zr) -> G1 {
        div_G1_Zr(&self, &other)
    }
}

impl Mul<G1> for Zr {
    type Output = G1;
    fn mul(self, other: G1) -> G1 {
        mul_G1_Zr(&other, &self)
    }
}

impl Mul<G1> for i64 {
    type Output = G1;
    fn mul(self, other: G1) -> G1 {
        Zr::from(self) * other
    }
}

impl Div<i64> for G1 {
    type Output = G1;
    fn div(self, other: i64) -> G1 {
        self / Zr::from(other)
    }
}

impl Mul<i64> for G1 {
    type Output = G1;
    fn mul(self, other: i64) -> G1 {
        self * Zr::from(other)
    }
}

impl AddAssign<G1> for G1 {
    fn add_assign(&mut self, other: G1) {
        *self = *self + other;
    }
}

impl SubAssign<G1> for G1 {
    fn sub_assign(&mut self, other: G1) {
        *self = *self - other;
    }
}

impl MulAssign<Zr> for G1 {
    fn mul_assign(&mut self, other: Zr) {
        *self = *self * other;
    }
}

impl DivAssign<Zr> for G1 {
    fn div_assign(&mut self, other: Zr) {
        *self = *self / other;
    }
}

impl MulAssign<i64> for G1 {
    fn mul_assign(&mut self, other: i64) {
        *self *= Zr::from(other);
    }
}

impl DivAssign<i64> for G1 {
    fn div_assign(&mut self, other: i64) {
        *self /= Zr::from(other);
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
pub struct G2([u8;G2_SIZE_AR160]);

impl G2 {
    pub fn new() -> G2 {
        G2(G2::wv())
    }
    
    fn wv() -> [u8; G2_SIZE_AR160] {
        [0u8;G2_SIZE_AR160]
    }
    
    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("G2", &self.base_vector())
    }

    pub fn from_str(s : &str) -> G2 {
        let mut v = G2::wv();
        hexstr_to_u8v(&s, &mut v);
        G2(v)
    }
}

impl fmt::Display for G2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Neg for G2 {
    type Output = G2;
    fn neg(self) -> G2 {
        neg_G2(&self)
    }
}

impl Add<G2> for G2 {
    type Output = G2;
    fn add(self, other: G2) -> G2 {
        add_G2_G2(&self, &other)
    }
}

impl Sub<G2> for G2 {
    type Output = G2;
    fn sub(self, other: G2) -> G2 {
        sub_G2_G2(&self, &other)
    }
}

impl Mul<Zr> for G2 {
    type Output = G2;
    fn mul(self, other: Zr) -> G2 {
        mul_G2_Zr(&self, &other)
    }
}

impl Mul<i64> for G2 {
    type Output = G2;
    fn mul(self, other: i64) -> G2 {
        self * Zr::from(other)
    }
}

impl Div<Zr> for G2 {
    type Output = G2;
    fn div(self, other: Zr) -> G2 {
        div_G2_Zr(&self, &other)
    }
}

impl Div<i64> for G2 {
    type Output = G2;
    fn div(self, other: i64) -> G2 {
        self / Zr::from(other)
    }
}

impl Mul<G2> for Zr {
    type Output = G2;
    fn mul(self, other: G2) -> G2 {
        mul_G2_Zr(&other, &self)
    }
}

impl Mul<G2> for i64 {
    type Output = G2;
    fn mul(self, other: G2) -> G2 {
        other * Zr::from(self)
    }
}

impl AddAssign<G2> for G2 {
    fn add_assign(&mut self, other: G2) {
        *self = *self + other;
    }
}

impl SubAssign<G2> for G2 {
    fn sub_assign(&mut self, other: G2) {
        *self = *self - other;
    }
}

impl MulAssign<Zr> for G2 {
    fn mul_assign(&mut self, other: Zr) {
        *self = *self * other;
    }
}

impl DivAssign<Zr> for G2 {
    fn div_assign(&mut self, other: Zr) {
        *self = *self / other;
    }
}

impl MulAssign<i64> for G2 {
    fn mul_assign(&mut self, other: i64) {
        *self *= Zr::from(other);
    }
}

impl DivAssign<i64> for G2 {
    fn div_assign(&mut self, other: i64) {
        *self /= Zr::from(other);
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
pub struct GT([u8;GT_SIZE_AR160]);

impl GT {
    pub fn new() -> GT {
        GT(GT::wv())
    }
    
    fn wv() -> [u8; GT_SIZE_AR160] {
        [0u8;GT_SIZE_AR160]
    }
    
    pub fn base_vector(&self) -> &[u8] {
        &self.0
    }


    pub fn to_str(&self) -> String {
        u8v_to_typed_str("GT", &self.base_vector())
    }
}

impl fmt::Display for GT {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Mul<GT> for GT {
    type Output = GT;
    fn mul(self, other: GT) -> GT {
        mul_GT_GT(&self, &other)
    }
}

impl Div<GT> for GT {
    type Output = GT;
    fn div(self, other: GT) -> GT {
        div_GT_GT(&self, &other)
    }
}

impl MulAssign<GT> for GT {
    fn mul_assign(&mut self, other: GT) {
        *self = *self * other;
    }
}

impl DivAssign<GT> for GT {
    fn div_assign(&mut self, other: GT) {
        *self = *self / other;
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
pub struct SecretKey (Zr);

impl SecretKey {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("SKey", &self.base_vector())
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

// -----------------------------------------
#[derive(Copy, Clone)]
pub struct PublicKey (G2);

impl PublicKey {
    pub fn base_vector(&self) -> &[u8] {
        self.0.base_vector()
    }

    pub fn to_str(&self) -> String {
        u8v_to_typed_str("PKey", &self.base_vector())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

// ------------------------------------------------------------------
// Key Generation & Checking

pub fn sign_hash(h : &Hash, skey : &SecretKey) -> G1 {
    // return a raw signature on a hash
    let v = G1::new();
    unsafe {
        rust_libpbc::sign_hash(
            PBC_CONTEXT_AR160 as u64,
            v.base_vector().as_ptr() as *mut _,
            skey.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            HASH_SIZE as u64);
    }
    v
}

pub fn check_hash(h : &Hash, sig : &G1, pkey : &PublicKey) -> bool {
    // check a hash with a raw signature, return t/f
    unsafe {
        0 == rust_libpbc::check_signature(
                PBC_CONTEXT_AR160 as u64,
                sig.base_vector().as_ptr() as *mut _,
                h.base_vector().as_ptr() as *mut _,
                HASH_SIZE as u64,
                pkey.base_vector().as_ptr() as *mut _)
    }
}

pub fn make_deterministic_keys(seed : &[u8]) -> (SecretKey, PublicKey, G1) {
    let h = hash(&seed);
    let sk = Zr::new();  // secret keys in Zr
    let pk = G2::new();  // public keys in G2
    unsafe {
        rust_libpbc::make_key_pair(
            PBC_CONTEXT_AR160 as u64,
            sk.base_vector().as_ptr() as *mut _,
            pk.base_vector().as_ptr() as *mut _,
            h.base_vector().as_ptr() as *mut _,
            HASH_SIZE as u64);
    }
    let hpk = hash(&pk.base_vector());
    let skey = SecretKey(sk);
    let pkey = PublicKey(pk);
    let sig  = sign_hash(&hpk, &skey);
    (skey, pkey, sig)
}

pub fn check_keying(pkey : &PublicKey, sig : &G1) -> bool {
    check_hash(&hash(&pkey.base_vector()), &sig, &pkey)
}

pub fn make_random_keys() -> (SecretKey, PublicKey, G1) {
    make_deterministic_keys(Zr::random().base_vector())
}

// ----------------------------------------------------------------
// Curve Arithmetic...

pub fn add_Zr_Zr(a : &Zr, b : &Zr) -> Zr {
    let ans = a.clone();
    unsafe {
        rust_libpbc::add_Zr_vals(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn sub_Zr_Zr(a : &Zr, b : &Zr) -> Zr {
    let ans = a.clone();
    unsafe {
        rust_libpbc::sub_Zr_vals(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn mul_Zr_Zr(a : &Zr, b : &Zr) -> Zr {
    let ans = a.clone();
    unsafe {
        rust_libpbc::mul_Zr_vals(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn div_Zr_Zr(a : &Zr, b : &Zr) -> Zr {
    let ans = a.clone();
    unsafe {
        rust_libpbc::div_Zr_vals(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn exp_Zr_Zr(a : &Zr, b : &Zr) -> Zr {
    let ans = a.clone();
    unsafe {
        rust_libpbc::exp_Zr_vals(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn neg_Zr(a : &Zr) -> Zr {
    let ans = a.clone();
    unsafe {
        rust_libpbc::neg_Zr_val(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn inv_Zr(a : &Zr) -> Zr {
    let ans = a.clone();
    unsafe {
        rust_libpbc::inv_Zr_val(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _);
    }
    ans
}

// ---------------------------------

pub fn mul_G1_Zr(a : &G1, b : &Zr) -> G1 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::exp_G1z(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn div_G1_Zr(a : &G1, b : &Zr) -> G1 {
    let invb = inv_Zr(&b);
    mul_G1_Zr(&a, &invb)
}

pub fn add_G1_G1(a : &G1, b : &G1) -> G1 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::add_G1_pts(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn sub_G1_G1(a : &G1, b : &G1) -> G1 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::sub_G1_pts(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn neg_G1(a : &G1) -> G1 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::neg_G1_pt(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _);
    }
    ans
}

// ------------------------------------------------------

pub fn mul_G2_Zr(a : &G2, b : &Zr) -> G2 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::exp_G2z(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn div_G2_Zr(a : &G2, b : &Zr) -> G2 {
    let invb = inv_Zr(&b);
    mul_G2_Zr(&a, &invb)
}

pub fn add_G2_G2(a : &G2, b : &G2) -> G2 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::add_G2_pts(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn sub_G2_G2(a : &G2, b : &G2) -> G2 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::sub_G2_pts(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn neg_G2(a : &G2) -> G2 {
    let ans = a.clone();
    unsafe {
        rust_libpbc::neg_G2_pt(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _);
    }
    ans
}

// -------------------------------------------------

pub fn compute_pairing(a : &G1, b : &G2) -> GT {
    let ans = GT::new();
    unsafe {
        rust_libpbc::compute_pairing(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            a.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn mul_GT_GT(a : &GT, b : &GT) -> GT {
    let ans = a.clone();
    unsafe {
        rust_libpbc::mul_GT_vals(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn div_GT_GT(a : &GT, b : &GT) -> GT {
    let ans = a.clone();
    unsafe {
        rust_libpbc::div_GT_vals(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn exp_GT_Zr(a : &GT, b : &Zr) -> GT {
    let ans = a.clone();
    unsafe {
        rust_libpbc::exp_GTz(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _,
            b.base_vector().as_ptr() as *mut _);
    }
    ans
}

pub fn inv_GT(a : &GT) -> GT {
    let ans = a.clone();
    unsafe {
        rust_libpbc::inv_GT_val(
            PBC_CONTEXT_AR160 as u64,
            ans.base_vector().as_ptr() as *mut _);
    }
    ans
}

// -------------------------------------------

impl G1 {
    pub fn generator() -> G1 {
        let u = G1::new();
        unsafe {
            rust_libpbc::get_g1(
                PBC_CONTEXT_AR160 as u64,
                u.base_vector().as_ptr() as *mut _,
                G1_SIZE_AR160 as u64);
        }
        u
    }

    pub fn from_hash(h : &Hash) -> G1 {
        let u = G1::new();
        unsafe {
            rust_libpbc::get_G1_from_hash(
                PBC_CONTEXT_AR160 as u64,
                u.base_vector().as_ptr() as *mut _,
                h.base_vector().as_ptr() as *mut _,
                HASH_SIZE as u64);
        }
        u
    }
}

impl G2 {
    pub fn generator() -> G2 {
        let v = G2::new();
        unsafe {
            rust_libpbc::get_g2(
                PBC_CONTEXT_AR160 as u64,
                v.base_vector().as_ptr() as *mut _,
                G1_SIZE_AR160 as u64);
        }
        v
    }

    pub fn from_hash(h : &Hash) -> G2 {
        let v = G2::new();
        unsafe {
            rust_libpbc::get_G2_from_hash(
                PBC_CONTEXT_AR160 as u64,
                v.base_vector().as_ptr() as *mut _,
                h.base_vector().as_ptr() as *mut _,
                HASH_SIZE as u64);
        }
        v
    }
}
