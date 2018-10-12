// utils.rs - general utility functions for vector handling
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
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// -------------------------------------------------------------------
// general utility functions

pub fn hexstr_to_u8v(s: &str, x: &mut [u8]) {
    // collect a vector of 8-bit values from a hex string.
    let nx = x.len();
    let mut pos = 0;
    let mut val: u8 = 0;
    let mut cct = 0;
    for c in s.chars() {
        if pos < nx {
            match c.to_digit(16) {
                Some(d) => {
                    val += d as u8;
                    cct += 1;
                    if (cct & 1) == 0 {
                        x[pos] = val;
                        pos += 1;
                        val = 0;
                    }
                    else {
                        val <<= 4;
                    }
                },
                None => panic!("Invalid hex digit")
            }
        }
        else {
            break;
        }
    }
    for ix in pos..nx {
        x[ix] = val;
        val = 0;
    }
}

pub fn u8v_to_hexstr(x : &[u8]) -> String {
    // produce a hexnum string from a byte vector
    let mut s = String::new();
    for ix in 0 .. x.len() {
        s.push_str(&format!("{:02x}", x[ix]));
    }
    s
}

pub fn u8v_to_typed_str(pref : &str, vec : &[u8]) -> String {
    // produce a type-prefixed hexnum from a byte vector
    let mut s = String::from(pref);
    s.push_str("(");
    s.push_str(&u8v_to_hexstr(&vec));
    s.push_str(")");
    s
}

