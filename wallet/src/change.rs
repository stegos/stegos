//! Wallet - Change Calculation.

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

use crate::error::*;
use std::collections::VecDeque;

/// Find appropriate inputs.
pub(crate) fn find_utxo<'a, I, T>(
    unspent_iter: I,
    sum: i64,
    fee: i64,
    max_inputs_in_tx: usize,
) -> Result<(Vec<T>, i64, i64), WalletError>
where
    I: IntoIterator<Item = (T, i64)>,
    T: Clone,
{
    assert!(sum >= 0);
    assert!(fee >= 0);
    let mut sorted: Vec<(i64, T)> = unspent_iter.into_iter().map(|(o, a)| (a, o)).collect();

    // TODO: brute-force all possible solutions.

    //
    // Naive algorithm - try to spent as much UTXO as possible.
    //

    // Sort in ascending order to eliminate as much outputs as possible
    sorted.sort_by_key(|(amount, _output)| *amount);
    let mut inputs: VecDeque<(i64, T)> = VecDeque::from(sorted);

    // Try to spend with a change.
    let mut spent: Vec<T> = Vec::new();
    let mut change: i64 = sum + fee;

    // Keep only one input that is more than amount.
    // Filter rest inputs bigger > sum.
    // This will force spending of smallest inputs.
    loop {
        if inputs.len() < 2 {
            break;
        }
        // if second input is bigger than sum, remove first.
        match inputs.get(inputs.len() - 2) {
            Some((next_amount, _)) if *next_amount >= change => {
                let _ = inputs.pop_back();
            }
            _ => break,
        }
    }

    loop {
        if spent.len() >= max_inputs_in_tx {
            break;
        }
        if change > 0 {
            if let Some((amount, output)) = inputs.pop_back() {
                change -= amount;
                spent.push(output);
                continue;
            } else {
                break; // no inputs left
            }
        }
        if change <= 0 {
            if let Some((amount, output)) = inputs.pop_front() {
                change -= amount;
                spent.push(output);
            } else {
                break; // no inputs left
            }
        }
    }

    if change > 0 {
        if !inputs.is_empty() {
            return Err(WalletError::TooManyInputs);
        }
        return Err(WalletError::NotEnoughTokens);
    }

    return Ok((spent, fee, -change));
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use stegos_crypto::hash::Hash;

    /// Check transaction signing and validation.
    #[test]
    pub fn test_find_utxo() {
        let mut unspent: Vec<(Hash, i64)> = Vec::new();
        let amounts: [i64; 5] = [100, 50, 10, 2, 1];
        for amount in amounts.iter() {
            let hash = Hash::digest(amount);
            unspent.push((hash, *amount));
        }

        const FEE: i64 = 1;
        const FEE_CHANGE: i64 = 2 * FEE;
        const MAX_INPUTS_IN_TX: usize = 3;

        let unspent_iter = unspent.iter().map(|(h, a)| (h, *a));
        let (spent, fee, change) =
            find_utxo(unspent_iter, 49, FEE_CHANGE, MAX_INPUTS_IN_TX).unwrap();
        assert_eq!(
            spent,
            vec![
                &Hash::digest(&100i64),
                &Hash::digest(&1i64),
                &Hash::digest(&2i64)
            ]
        );
        assert_eq!(fee, FEE_CHANGE);
        assert_eq!(change, 52);

        let unspent_iter = unspent.iter().map(|(h, a)| (h, *a));
        let (spent, fee, change) =
            find_utxo(unspent_iter, 13 - FEE_CHANGE, FEE_CHANGE, MAX_INPUTS_IN_TX).unwrap();
        assert_eq!(
            spent,
            vec![
                &Hash::digest(&50i64),
                &Hash::digest(&1i64),
                &Hash::digest(&2i64)
            ]
        );
        assert_eq!(fee, FEE_CHANGE);
        assert_eq!(change, 40);

        // Without change.
        let unspent_iter = unspent.iter().map(|(h, a)| (h, *a));
        let (spent, fee, change) =
            find_utxo(unspent_iter, 163 - FEE_CHANGE, FEE_CHANGE, amounts.len()).unwrap();
        assert_eq!(
            spent,
            vec![
                &Hash::digest(&100i64),
                &Hash::digest(&50i64),
                &Hash::digest(&10i64),
                &Hash::digest(&2i64),
                &Hash::digest(&1i64),
            ]
        );
        assert_eq!(fee, FEE_CHANGE);
        assert_eq!(change, 0);

        // With change.
        let unspent_iter = unspent.iter().map(|(h, a)| (h, *a));
        let (spent, fee, change) =
            find_utxo(unspent_iter, 5, FEE_CHANGE, MAX_INPUTS_IN_TX).unwrap();
        assert_eq!(
            spent,
            vec![
                &Hash::digest(&10i64),
                &Hash::digest(&1i64),
                &Hash::digest(&2i64),
            ]
        );
        assert_eq!(fee, FEE_CHANGE);
        assert_eq!(change, 6);

        //TooManyInputs
        let unspent_iter = unspent.iter().map(|(h, a)| (h, *a));
        match find_utxo(unspent_iter, 163, FEE_CHANGE, MAX_INPUTS_IN_TX) {
            Err(WalletError::TooManyInputs) => {}
            e => panic!("error = {:?}", e),
        };

        // NotEnoughTokens
        let unspent_iter = unspent.iter().map(|(h, a)| (h, *a));
        match find_utxo(unspent_iter, 164, FEE_CHANGE, unspent.len()) {
            Err(WalletError::NotEnoughTokens) => {}
            e => panic!("error = {:?}", e),
        };
    }
}
