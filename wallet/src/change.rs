//! Wallet - Change Calculation.

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

use crate::error::*;
use log::*;
use std::collections::HashMap;
use stegos_crypto::hash::Hash;

/// Find UTXO with exact value.
pub(crate) fn find_utxo_exact<T: Clone>(unspent: &HashMap<Hash, (T, i64)>, sum: i64) -> Option<T> {
    for (hash, (output, amount)) in unspent {
        if *amount == sum {
            debug!("Use UTXO: hash={}, amount={}", hash, amount);
            return Some(output.clone());
        }
    }
    None
}

/// Find appropriate UTXO to spent and calculate a change.
pub(crate) fn find_utxo<T: Clone>(
    unspent: &HashMap<Hash, (T, i64)>,
    mut sum: i64,
) -> Result<(Vec<T>, i64), WalletError> {
    assert!(sum >= 0);
    let mut sorted: Vec<(i64, Hash)> = unspent
        .iter()
        .map(|(hash, (_output, amount))| (*amount, hash.clone()))
        .collect();
    // Sort ascending in order to eliminate as much outputs as possible
    sorted.sort_by_key(|(amount, _hash)| *amount);

    // Naive algorithm - try to spent as much UTXO as possible.
    let mut spent = Vec::<T>::new();
    for (amount, hash) in sorted.drain(..) {
        if sum <= 0 {
            break;
        }
        sum -= amount;
        let (output, _amount) = unspent.get(&hash).unwrap();
        spent.push(output.clone());
        debug!("Use UTXO: hash={}, amount={}", hash, amount);
    }
    drop(unspent);

    if sum > 0 {
        return Err(WalletError::NotEnoughMoney);
    }

    let change = -sum;
    return Ok((spent, change));
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Check transaction signing and validation.
    #[test]
    pub fn test_find_utxo() {
        let mut unspent = HashMap::<Hash, (Hash, i64)>::new();
        let amounts: [i64; 5] = [100, 50, 10, 2, 1];
        for amount in amounts.iter() {
            let hash = Hash::digest(amount);
            unspent.insert(hash, (hash.clone(), *amount));
        }

        let (spent, change) = find_utxo(&unspent, 1).unwrap();
        assert_eq!(spent, vec![Hash::digest(&1i64)]);
        assert_eq!(change, 0);

        let (spent, change) = find_utxo(&unspent, 2).unwrap();
        assert_eq!(spent, vec![Hash::digest(&1i64), Hash::digest(&2i64)]);
        assert_eq!(change, 1);

        let (spent, change) = find_utxo(&unspent, 5).unwrap();
        assert_eq!(
            spent,
            vec![
                Hash::digest(&1i64),
                Hash::digest(&2i64),
                Hash::digest(&10i64)
            ]
        );
        assert_eq!(change, 8);

        let (spent, change) = find_utxo(&unspent, 163).unwrap();
        assert_eq!(
            spent,
            vec![
                Hash::digest(&1i64),
                Hash::digest(&2i64),
                Hash::digest(&10i64),
                Hash::digest(&50i64),
                Hash::digest(&100i64),
            ]
        );
        assert_eq!(change, 0);

        assert!(find_utxo(&unspent, 164).is_err());
    }
}
