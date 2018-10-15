// lev32.rs -- 32-byte little-endian vectors
//
// DM/Emotiq 10/18
// MIT License
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
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFrINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FrOM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


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
