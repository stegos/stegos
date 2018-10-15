
use super::*;

// -----------------------------------------------------------------
// window vector of 4-bit values, used for fast multiply of curve points

pub const PANES  : usize  = 64; // nbr of 4-bit nibbles in 256-bit numbers

#[repr(C)]
pub struct WinVec(pub [i8;PANES]);

pub const WINVEC_INIT: WinVec = WinVec([0;PANES]);

impl From<FrUnscaled> for WinVec {
    fn from(x : FrUnscaled) -> WinVec {
        let tmp = LEV32::from(x.0);
        let mut wv = WINVEC_INIT;
        cwin4(&tmp, &mut wv);
        wv
    }
}

impl From<i64> for WinVec {
    fn from(x : i64) -> WinVec {
        WinVec::from(FrUnscaled::from(x))
    }
}

impl From<Fr> for WinVec {
    fn from(x : Fr) -> WinVec {
        WinVec::from(FrUnscaled::from(x))
    }
}

// convert bignum string to 4-bit LE window vector
fn str_to_winvec(s: &str, w: &mut WinVec) {
    let mut qv: [u8;32] = [0;32];
    str_to_bin8(s, &mut qv);
    println!("multiplier: {}", LEV32(qv));
    cwin4(&LEV32(qv), w);
}

// convert incoming LEV32 (byte vector) into a little endian vector
// of bipolar window values [-8..8)
fn cwin4(q: &LEV32, w: &mut WinVec) {
    // convert incoming N to bipolar 4-bit window vector - no branching
    let mut cy = 0;
    let mut cvbip = | v_in | {
        let mut v = cy + (v_in as i8);
        cy = v >> 3;
        cy |= cy >> 1;
        cy &= 1;
        v -= cy << 4;
        v
    };
    
    for ix in 0..32 {
        let byt = q.0[ix];
        let v = cvbip(byt & 15);
        let jx = 2*ix;
        w.0[jx] = v;
        let v = cvbip(byt >> 4);
        w.0[jx+1] = v;
    }
}


