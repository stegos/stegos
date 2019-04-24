// show_utxo_chunks
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
//

#![allow(unused)]
#![deny(warnings)]
#![allow(non_snake_case)]

use std::time::SystemTime;
use stegos_blockchain::Output;
use stegos_blockchain::Transaction;
use stegos_blockchain::{PaymentOutput, PaymentPayloadData};
use stegos_crypto::curve1174::cpt::make_random_keys;
use stegos_crypto::curve1174::cpt::Pt;
use stegos_crypto::curve1174::cpt::PublicKey;
use stegos_crypto::curve1174::cpt::SchnorrSig;
use stegos_crypto::curve1174::cpt::SecretKey;
use stegos_crypto::curve1174::ecpt::ECp;
use stegos_crypto::curve1174::fields::Fr;
use stegos_crypto::hash::Hash;
use stegos_crypto::hash::{Hashable, Hasher, HASH_SIZE};
use stegos_serialization::traits::ProtoConvert;

use stegos_crypto::dicemix::*;

fn main() {
    // Determine number of DiceMix chunks needed to support our UTXO's
    let (skey, pkey) = make_random_keys();
    let tstamp = SystemTime::now();
    let data = PaymentPayloadData::Comment("Testing".to_string());
    let (out, gamma) = PaymentOutput::with_payload(tstamp, &skey, &pkey, 1500, data)
        .expect("Can't produce payment output");
    let msg = out.into_buffer().expect("can't serialize UTXO");
    println!("UTXO len = {}", msg.len());
    let row = split_message(&msg, None);
    println!("Row len = {}", row.len());
}
