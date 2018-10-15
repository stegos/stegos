use super::*;

// -----------------------------------------------------------------
// type LEV32 represents a 256-bit bignum as a little-endian 32-byte vector

#[derive(Copy, Clone)]
#[repr(C)]
pub struct LEV32(pub [u8;32]);

impl fmt::Display for LEV32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LEV32({})", self.nbr_str())
    }
}

impl LEV32 {
    fn nbr_str(&self) -> String {
        let LEV32(qv) = self;
        let v = unsafe { mem::transmute::<[u8;32], [u64;4]>(*qv) };
        basic_nbr_str(&v)
    }
}

// collect a vector of 8-bit values from a hex string.
// the vector has little-endian order
pub fn str_to_bin8(s: &str, x: &mut [u8]) {
    let nx = x.len();
    let mut bf = 0;
    let mut bw = 0;
    let mut val: u8 = 0;
    for c in s.chars().rev() {
        match c.to_digit(16) {
            Some(d) => {
                val |= (d as u8) << bf;
                bf += 4;
                if bf == 8 {
                    if bw < nx {
                        x[bw] = val;
                    }
                    bf = 0;
                    bw += 1;
                    val = 0;
                }
            },
            None => panic!("Invalid hex digit")
        }
    }
    if bf > 0 && bw < nx {
        x[bw] = val;
    }
}
