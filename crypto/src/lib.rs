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

#![deny(warnings)]

pub mod aont;
pub mod bulletproofs;
#[cfg(feature = "flint")]
pub mod dicemix;
pub mod hash;
pub mod keying;
pub mod pbc;
pub mod protos;
pub mod scc;
pub mod utils;
pub mod vdf;

use bech32::Error as Bech32Error;
use failure::Fail;
use hex;

static mut NETWORK_PREFIX: &'static str = "dev";

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
        _0, _1
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

    // If someone requests a field value, e.g., Fr::to_i64() and number
    // is too large to allow that conversion...
    #[fail(display = "Field value is too large for requested conversion")]
    TooLarge,

    #[fail(display = "Encrypted Key has incorrect Signature")]
    BadKeyingSignature,
    #[fail(display = "Invalid ECC Point")]
    InvalidPoint,

    #[fail(display = "Point in small subgroup")]
    InSmallSubgroup,

    #[fail(display = "Point not in principal subgroup")]
    NotInPrincipalSubgroup,

    #[fail(display = "Not an AONT ciphertext")]
    InvalidAontDecryption,
    #[fail(display = "Bech32 error = {}", _0)]
    Bech32Error(Bech32Error),
    #[fail(display = "Incorrect network prefix: expected={}, actual={}", _0, _1)]
    IncorrectNetworkPrefix(&'static str, String),
    #[fail(display = "Invalid SubKeying")]
    InvalidSubKeying,
    #[fail(display = "Invalid Decryption")]
    InvalidDecryption,
    #[fail(display = "Invalid VRF Randomness")]
    InvalidVRFRandomness,
    #[fail(display = "Invalid VRF Source")]
    InvalidVRFSource,
    #[fail(display = "Invalid VDF Proof")]
    InvalidVDFProof,
    #[fail(display = "Invalid VDF complexity: got={}", _0)]
    InvalidVDFComplexity(u64),
    #[fail(
        display = "Unexpected VDF complexity: min={}, max={}, got={}",
        _0, _1, _2
    )]
    UnexpectedVDFComplexity(u64, u64, u64),
    #[fail(display = "Network prefix already set to: {}", _0)]
    NetworkPrefixAlreadySet(&'static str),
    #[fail(display = "Failed to set network prefix from two threads.")]
    NetworkPrefixSetFailed,

    #[fail(display = "No solution in DiceMix")]
    DiceMixNoSolution,
    #[fail(display = "Non-monic root in DiceMix")]
    DiceMixNonMonicRoot,
    #[fail(display = "Not enough roots in DiceMix")]
    DiceMixNotEnoughRoots,
    #[fail(display = "Internal error in flint solver, return value = {}", _0)]
    DiceMixInternalError(i32),
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

impl From<Bech32Error> for CryptoError {
    fn from(error: Bech32Error) -> Self {
        CryptoError::Bech32Error(error)
    }
}

use std::sync::atomic::{AtomicUsize, Ordering};

static STATE: AtomicUsize = AtomicUsize::new(UNINITIALIZED);
const UNINITIALIZED: usize = 0;
const INITIALIZING: usize = 1;
const INITIALIZED: usize = 2;

/// Initialize crypto to work with specific network prefix.
/// Reserved network prefixes:
/// stg - stegos mainnet;
/// stt - stegos testnet;
/// str - stegos devnet;
/// dev - local stegos dev;
pub fn set_network_prefix(prefix: &'static str) -> Result<(), CryptoError> {
    unsafe {
        match STATE.compare_and_swap(UNINITIALIZED, INITIALIZING, Ordering::SeqCst) {
            UNINITIALIZED => {
                NETWORK_PREFIX = prefix;
                STATE.store(INITIALIZED, Ordering::SeqCst);
                Ok(())
            }
            INITIALIZING => {
                while STATE.load(Ordering::SeqCst) == INITIALIZING {}
                Err(CryptoError::NetworkPrefixSetFailed)
            }
            _ => Err(CryptoError::NetworkPrefixAlreadySet(NETWORK_PREFIX)),
        }
    }
}

pub fn get_network_prefix() -> &'static str {
    unsafe {
        if STATE.load(Ordering::SeqCst) == INITIALIZED {
            NETWORK_PREFIX
        } else {
            panic!("Network prefix was not initialized.")
        }
    }
}

pub fn init_test_network_prefix() {
    let _ = set_network_prefix("dev");
}
