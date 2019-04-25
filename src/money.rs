///! Decimal money parser.
//
// Copyright (c) 2019 Stegos AG
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
use failure::{bail, Error};

const MONEY_MAIN_PRECISION: usize = 12;
const MONEY_FRAC_PRECISION: usize = 6;
const MONEY_UNIT: i64 = 1_000_000; // 6 digits.
const MONEY_MAX: i64 = 1_000_000_000_000; // 12 digits.

pub fn format_money(amount: i64) -> String {
    if amount % MONEY_UNIT == 0 {
        format!("{}", amount / MONEY_UNIT)
    } else {
        format!("{:}.{:0>6}", amount / MONEY_UNIT, amount % MONEY_UNIT)
    }
}

pub fn parse_money(amount: &str) -> Result<i64, Error> {
    let (main, frac) = if let Some(sep) = amount.rfind('.') {
        let (main, frac) = amount.split_at(sep);
        let frac = &frac[1..]; // skip separator itself.
        let frac_precision = frac.len();
        if frac_precision > MONEY_FRAC_PRECISION {
            bail!(
                "Invalid amount '{}': too many digits after decimal point",
                amount
            );
        }
        let frac = match frac.parse::<u64>() {
            Ok(frac) => frac as i64,
            Err(_e) => bail!(
                "Invalid amount '{}': failed to parse fractional part",
                amount
            ),
        };
        let frac = frac * 10i64.pow((MONEY_FRAC_PRECISION - frac_precision) as u32);
        (main, frac)
    } else {
        (amount, 0i64)
    };

    if main.len() > MONEY_MAIN_PRECISION {
        bail!(
            "Invalid amount '{}': too many digits before decimal point",
            amount
        );
    }
    let main = match main.parse::<u64>() {
        Ok(main) => main as i64,
        Err(_e) => bail!("Invalid amount '{}': failed to parse main part", amount),
    };
    assert!(main < MONEY_MAX);
    assert!(frac < MONEY_UNIT);
    return Ok(main * MONEY_UNIT + frac);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn money() {
        let test_values = vec![
            ("0", 0, "0"),
            ("5", 5_000_000, "5"),
            ("5.0", 5_000_000, "5"),
            ("5.00", 5_000_000, "5"),
            ("5.000", 5_000_000, "5"),
            ("5.0000", 5_000_000, "5"),
            ("5.00000", 5_000_000, "5"),
            ("5.000000", 5_000_000, "5"),
            ("5.9", 5_900_000, "5.900000"),
            ("5.99", 5_990_000, "5.990000"),
            ("5.999", 5_999_000, "5.999000"),
            ("5.9999", 5_999_900, "5.999900"),
            ("5.99999", 5_999_990, "5.999990"),
            ("5.999999", 5_999_999, "5.999999"),
            ("5", 5_000_000, "5"),
            ("5.0", 5_000_000, "5"),
            ("5.3", 5_300_000, "5.300000"),
            ("5.03", 5_030_000, "5.030000"),
            ("5.003", 5_003_000, "5.003000"),
            ("5.0003", 5_000_300, "5.000300"),
            ("5.00003", 5_000_030, "5.000030"),
            ("5.000003", 5_000_003, "5.000003"),
            ("999999999999", 999_999_999_999_000_000, "999999999999"),
            (
                "999999999999.999999",
                999_999_999_999_999_999,
                "999999999999.999999",
            ),
        ];

        for (sval, ival, sval2) in test_values {
            let ival2 = parse_money(sval).expect("valid");
            assert_eq!(ival, ival2);
            assert_eq!(sval2, format_money(ival));
        }

        parse_money("1000000000000").unwrap_err();
        parse_money("0.0000000").unwrap_err();
        parse_money("a.0").unwrap_err();
        parse_money("0.b").unwrap_err();
    }
}
