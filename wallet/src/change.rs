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
use log::trace;
use std::collections::VecDeque;
use stegos_blockchain::Timestamp;

/// Find appropriate inputs.
pub(crate) fn find_utxo<'a, I, T>(
    unspent_iter: I,
    sum: i64,
    fee: i64,
    fee_change: i64,
    last_macro_block_timestamp: Timestamp,
    max_inputs_in_tx: usize,
) -> Result<(Vec<&'a T>, i64, i64), WalletError>
where
    I: IntoIterator<Item = (&'a T, i64, Option<Timestamp>)>,
{
    assert!(sum >= 0);
    assert!(fee >= 0);
    assert!(fee_change >= 0);
    let mut sorted: Vec<(i64, &T)> = Vec::new();
    for (output, amount, time) in unspent_iter {
        if let Some(time) = time {
            if time >= last_macro_block_timestamp {
                trace!(
                    "Ignoring output because its locked, locked_time={:?}, \
                     macro_block_time={:?}",
                    time,
                    last_macro_block_timestamp
                );
                continue;
            }
        }
        if amount == sum + fee {
            return Ok((vec![output], fee, 0i64));
        }
        sorted.push((amount, output));
    }

    // TODO: brute-force all possible solutions.

    //
    // Naive algorithm - try to spent as much UTXO as possible.
    //

    // Sort in ascending order to eliminate as much outputs as possible
    sorted.sort_by_key(|(amount, _output)| *amount);
    let mut inputs: VecDeque<(i64, &T)> = VecDeque::from(sorted);

    // Try to spend without a change.
    let mut spent: Vec<&T> = Vec::new();
    let mut change: i64 = sum + fee;
    for (amount, output) in inputs.iter() {
        change -= *amount;
        spent.push(*output);
        if change <= 0 || spent.len() >= max_inputs_in_tx {
            break;
        }
    }
    if change == 0 {
        return Ok((spent, fee, 0));
    }

    // Try to spend with a change.
    spent.clear();
    let mut change: i64 = sum + fee_change;
    loop {
        if spent.len() >= max_inputs_in_tx {
            break;
        }
        if change > 0 {
            if let Some((amount, output)) = inputs.pop_back() {
                change -= amount;
                spent.push(&*output);
                continue;
            } else {
                break; // no inputs left
            }
        }
        if change <= 0 {
            if let Some((amount, output)) = inputs.pop_front() {
                change -= amount;
                spent.push(&*output);
            } else {
                break; // no inputs left
            }
        }
    }

    if change > 0 {
        return Err(WalletError::NotEnoughMoney);
    }

    return Ok((spent, fee_change, -change));
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use stegos_crypto::hash::Hash;

    /// Check transaction signing and validation.
    #[test]
    pub fn test_find_utxo() {
        let mut unspent: Vec<(Hash, i64, _)> = Vec::new();
        let amounts: [i64; 5] = [100, 50, 10, 2, 1];
        for amount in amounts.iter() {
            let hash = Hash::digest(amount);
            unspent.push((hash, *amount, None));
        }

        const FEE: i64 = 1;
        const FEE_CHANGE: i64 = 2 * FEE;
        const MAX_INPUTS_IN_TX: usize = 3;

        // Without change.
        let unspent_iter = unspent.iter().map(|(h, a, t)| (h, *a, t.clone()));
        let (spent, fee, change) = find_utxo(
            unspent_iter,
            49,
            FEE,
            FEE_CHANGE,
            Timestamp::now(),
            MAX_INPUTS_IN_TX,
        )
        .unwrap();
        assert_eq!(spent, vec![&Hash::digest(&50i64)]);
        assert_eq!(fee, FEE);
        assert_eq!(change, 0);

        // Without change.
        let unspent_iter = unspent.iter().map(|(h, a, t)| (h, *a, t.clone()));
        let (spent, fee, change) = find_utxo(
            unspent_iter,
            13 - FEE,
            FEE,
            FEE_CHANGE,
            Timestamp::now(),
            MAX_INPUTS_IN_TX,
        )
        .unwrap();
        assert_eq!(
            spent,
            vec![
                &Hash::digest(&1i64),
                &Hash::digest(&2i64),
                &Hash::digest(&10i64)
            ]
        );
        assert_eq!(fee, FEE);
        assert_eq!(change, 0);

        // Without change.
        let unspent_iter = unspent.iter().map(|(h, a, t)| (h, *a, t.clone()));
        let (spent, fee, change) = find_utxo(
            unspent_iter,
            163 - FEE,
            FEE,
            FEE_CHANGE,
            Timestamp::now(),
            10,
        )
        .unwrap();
        assert_eq!(
            spent,
            vec![
                &Hash::digest(&1i64),
                &Hash::digest(&2i64),
                &Hash::digest(&10i64),
                &Hash::digest(&50i64),
                &Hash::digest(&100i64),
            ]
        );
        assert_eq!(fee, FEE);
        assert_eq!(change, 0);

        // With change.
        let unspent_iter = unspent.iter().map(|(h, a, t)| (h, *a, t.clone()));
        let (spent, fee, change) = find_utxo(
            unspent_iter,
            5,
            FEE,
            FEE_CHANGE,
            Timestamp::now(),
            MAX_INPUTS_IN_TX,
        )
        .unwrap();
        assert_eq!(
            spent,
            vec![
                &Hash::digest(&100i64),
                &Hash::digest(&1i64),
                &Hash::digest(&2i64),
            ]
        );
        assert_eq!(fee, FEE_CHANGE);
        assert_eq!(change, 96);

        // NotEnoughMoney
        let unspent_iter = unspent.iter().map(|(h, a, t)| (h, *a, t.clone()));
        match find_utxo(
            unspent_iter,
            164,
            FEE,
            FEE_CHANGE,
            Timestamp::now(),
            MAX_INPUTS_IN_TX,
        ) {
            Err(WalletError::NotEnoughMoney) => {}
            _ => panic!(),
        };
    }
}
