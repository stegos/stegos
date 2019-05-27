//! Blockchain Implementation.

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

mod block;
mod blockchain;
mod config;
pub mod election;
mod error;
mod escrow;
mod genesis;
mod merkle;
mod metrics;
mod multisignature;
pub mod mvcc;
mod output;
pub mod protos;
mod slashing;
mod storage;
mod transaction;
mod validation;
pub mod view_changes;

pub use crate::block::*;
pub use crate::blockchain::*;
pub use crate::config::*;
pub use crate::election::{mix, ElectionInfo, ElectionResult, StakersGroup};
pub use crate::error::*;
pub use crate::escrow::*;
pub use crate::genesis::*;
pub use crate::merkle::*;
pub use crate::multisignature::*;
pub use crate::output::*;
pub use crate::slashing::*;
pub use crate::storage::*;
pub use crate::transaction::*;
