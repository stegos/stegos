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

extern crate crypto;
extern crate gmp;
extern crate hex;
extern crate lazy_static;
extern crate parking_lot;
extern crate rand;
extern crate rust_libpbc;
extern crate sha3;
#[macro_use]
extern crate log;
extern crate failure;
#[macro_use]
extern crate failure_derive;

pub mod bulletproofs;
pub mod curve1174;
pub mod hash;
pub mod keying;
pub mod pbc;
pub mod utils;

#[derive(Debug, Fail)]
pub enum CryptoError {
    /// Not Quadratic Residue
    #[fail(display = "Quadratic Residue")]
    NotQuadraticResidue,
    /// Point Not OnCurve
    #[fail(display = "Point is not on a curve")]
    PointNotOnCurve,
    /// Trying to coerce from incorrecte byte array
    #[fail(
        display = "Invalid binary string length. Expected: {}, Got: {}",
        _0,
        _1
    )]
    InvalidBinaryLength(usize, usize),
    /// An invalid character was found. Valid ones are: `0...9`, `a...f`
    #[fail(display = "Invalid hex characters")]
    InvalidHexCharacter,
    /// A hex string's length needs to be even, as two digits correspond to
    /// one byte.
    #[fail(display = "Odd number of digits in hex string")]
    OddHexLength,
    /// If the hex string is decoded into a fixed sized container, such as an
    /// array, the hex string's length * 2 has to match the container's
    /// length.
    #[fail(display = "Invalid hex string length")]
    InvalidHexLength,
}

impl From<hex::FromHexError> for CryptoError {
    fn from(error: hex::FromHexError) -> Self {
        match error {
            hex::FromHexError::InvalidHexCharacter { .. } => CryptoError::InvalidHexCharacter,
            hex::FromHexError::InvalidStringLength => CryptoError::InvalidHexLength,
            hex::FromHexError::OddLength => CryptoError::OddHexLength,
        }
    }
}
