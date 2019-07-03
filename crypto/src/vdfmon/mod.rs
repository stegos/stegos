//! vdf - Exploratory code for Verifiable Delay Functions (VDF)

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

#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused)]

extern crate vdf;
use std::time::SystemTime;
use vdf::{
    InvalidIterations, InvalidProof, PietrzakVDF, PietrzakVDFParams, VDFParams,
    WesolowskiVDFParams, VDF,
};

pub struct VDFMon {
    // One of these constructed by new() on each validator node
    pub vdf: PietrzakVDF, // a VDF prover / validator object - treat as immutable
    pub duration: f32,    // expected durations for this VDFMon - treat as immutable
    pub complexity: u64,  // current complexity level for VDFMon - mutable for epoch adjustments
    pub tmrec: Vec<SystemTime>, // record of block timestamps seen during an Epoch
}

pub struct Stats {
    // used internally when analyzing the epoch timestamps
    pub mn: f32,   // mean of inter-block periods (sec)
    pub sd: f32,   // standard deviation of measurements
    pub sdmn: f32, // standard deviation of mean measurement
    pub twt: f32,  // effective number of contributing measurements
}

// ----------------------------------------------------------
// Recommended use:
//
//    All nodes call VDFMon::new(interblock_duration) at startup
//    The interblock_duration argument should be the f32 numnber of
//    seconds desired for the time period betweeen issuance of new blocks.
//
//    When a Leader node assembles a new block, he should check to see
//    if the mempool can immediately furnish sufficient transactions to fill
//    the block with TXOUT UTXO's. If so the Leader just assembles a block.
//
//    Otherwise, the leader should spawn parallel activities of filling a
//    block with available UTXO's, and computing a VDF proof. The proof can
//    be fired off by calling VDFMon::prove(), with an agreed-upon challenge
//    value, from one of the two parallel forks. Then the leader should wait
//    for the two parallel forks to join.
//
//    In either case, at the end of block stuffing and join, the Leader
//    should fill in the block header timestamp with the SystemTime::now()
//    obtained at that momemt, and should also call VDFMon::add_timestmp()
//    with that timestamp.
//
//    If the leader is constructing a micro-block, then this is all that is
//    needed.
//
//    If the Leader is constructing a macro-block, then they must also
//    compute and publish a new VDF Complexity value for use during the
//    next epoch. Leader obtains new VDF Complexity by calling
//    VDFMon::update_for_next_epoch(). This should be done after first adding
//    the new block timestamp as discussed above.
//
//    All Nodes: At system startup
/*
        let mon = VDFMon::new(desired_interblock_period);
*/
//
//    Leader Node: Block construction
/*
        if mempool.has_sufficient_utxos() {
            construct_block();
        } else {
            const PROOF_LEN : usize = 258;
            let mut proof = [0u8; PROOF_LEN];
            let vdf_fn = {||
                match mon.prove(challenge) {
                    Ok(p) => { proof.copy_bytes(p); },
                    Err(e) => {
                        /* should never happen */
                        panic!("Can't happen");
                    }
                }
            };
            let assemble_block_fn = { ||
                construct_block();
            };
            Rayon::join(&vdf_fn, &assemble_block_fn);
            stuff_proof_into_block_header(&proof);
        }
        let tm = SystemTime::now();
        stuff_timestamp_into_block_header(tm);
        mon.add_timestamp(tm);
        //
        // the following only happens for MacroBlocks
        //
        if constructing_macroblock() {
            let cmplx = mon.complexity_for_next_epoch();
            stuff_new_VDF_complexity_into_block_header(cmplx);
        }
        publish_block();
*/

//
//     All other validator nodes simply call either of
//       VDFMon::validate_microblock(), or
//       VDFMon::validate_epoch_macroblock(), whichever is needed.
//     Both functions expect:
//       1. the agreed-upon challenge used by the Leader
//          to compute a VDF Proof,
//       2. the timestamp recorded in the block header being validated,
//       3. the VDF Proof as Some(proof) if present, or None of there is
//          no VDF proof in the block header. [In the second case the block
//          must be fully stuffed with UTXOs to be considered valid.]
//       4. And only in the case of validate_epoch_macroblock(), the value
//          of the VDF Complexity proposed by the Leader as published in the
//          new macro-block header.
//
//     When validator nodes call either of these functions, the VDF Proof
//     is checked, when present, and the timestamp of the block is added to
//     the ordered list of timestamps maintained by the VDFMon object.
//
//     When calling validate_epoch_macroblock(), the new proposed VDF Complexity
//     level is also checked for reasonableness.
//
//  Validator Nodes: On every new block
/*
        let blk = get_new_proposed_block();
        blk.perform_other_validation_chores()?;

        // Validate VDF in block...
        let proof = if blk.has_vdf_proof() { Some(blk.vdf_proof) } else { None };
        if blk.is_macroblock() {
            mon.validate_epoch_macroblock(challenge, proof, blk.timestamp, blk.vdf_complexity)?;
        } else {
            mon.validate_microblock(challenge, proof, blk.timestamp)?;
        }
*/
//
// After a new MacroBlock has been published to the blockchain,
// all nodes should call:
//
//     VDFMon::set_complexity_level(&mut mon, new_complexity: u64);
//
// This both, sets the new complexity level into the VDFMon object,
// and resets the timestamp list, emptying it, and placing the last timestamp
// as the first entry.
// ------------------------------------------------------------------

impl VDFMon {
    // ------------------------------------------------------
    // Functions called by all nodes

    pub fn new(duration: u32) -> Self {
        // duration in seconds - expected duration
        // Constructs and returns a new VDFMon object. All validators
        // will call this during startup.
        //
        // The constants used here were derived from timing tests
        // performed on my local machine. They are not expected to hold
        // across a cluster of other machine, but they serve as a starting point.
        //
        // The running assumption here is that the constant overhead of
        // VDF proving will be very small compared to desired durations.
        // Hence we can reasonably scale complexity levels by the ratio of
        // desired_duration :: measured_duration.
        //
        assert!(duration > 1); // must have at least 2s to overcome overhead
        let duration = duration as f32;
        let cmplx = (52429.5 + (duration - 10.59) * 5626.0) as u64;
        VDFMon {
            vdf: PietrzakVDFParams(2048).new(),
            duration,
            complexity: cmplx,
            tmrec: Vec::<SystemTime>::new(),
        }
    }

    pub fn set_complexity_level(&mut self, complexity: u64) {
        // Sets a new complexity level for VDF proofs
        // and clears out the block timestamp record in preparation
        // for next epoch.
        //
        // The last timestamp in the list is pushed as the first one
        // in the newly cleared list.
        //
        // This gets called by all nodes upon official acceptance
        // of a new macroblock. They should all reset their timestamp lists
        // and establish a new complexity level for VDF proofs over the next epoch.
        //
        self.complexity = complexity;
        if self.tmrec.is_empty() {
            self.tmrec.push(SystemTime::now()); // dummy seed in case of misuse
        }
        // Last timestamp of previous list becomes first one
        // in list for new epoch
        let nel = self.tmrec.len();
        let last1 = self.tmrec[nel - 1];
        self.tmrec.clear();
        self.tmrec.push(last1);
    }

    // ------------------------------------------------------
    // Functions called only by Leader node

    pub fn prove(&self, challenge: &[u8]) -> Result<Vec<u8>, InvalidIterations> {
        // Leader nodes call this function from a closure in a Rayon::join() to
        // perform VDF proving in parallel with block construction acitivities.
        //
        // When the join() finishes, we will have delayed by a deterministic period
        // in one fork, and producing a VDF proof for inclusion in the block header.
        self.vdf.solve(challenge, self.complexity)
    }

    pub fn add_timestamp(&mut self, new_timestamp: SystemTime) {
        // Only the Leader node should ever call this function directly,
        // with the timestamp that he plants into the new block header.
        //
        // Leader should call this with the SystemTime obtained after
        // the VDF proof has been obtained (if one is being computed),
        // and after block stuffing is finished. The timestamp here
        // should be the one being recorded in the new block header.
        //
        // All other validator nodes indirectly have this function called
        // whenver they validate a VDFMon.
        //
        // This function updates the VDF timestamp list
        // for every block seen published during an Epoch.
        //
        self.tmrec.push(new_timestamp);
    }

    pub fn complexity_for_next_epoch(self) -> u64 {
        // Analyze the time record of each block that we accumulated,
        // and adjust the complexity to reach our expected duration
        // over the next epoch.
        // Returns the newly computed complexity level.
        //
        // This function is called by Leader node to obtain an updated
        // complexity level for next Epoch, which becomes published in the
        // block header for all validator nodes to see.
        //
        // Validator nodes will call validate() upon seeing it, along with our
        // published VDF proof.
        // If the proof validates, and they deem our updated complexity level
        // as within acceptable bounds, then they will update their own VDFMon's
        // to match.
        //
        if self.tmrec.len() > 1 {
            // At system start we begin with an empty timestamp list.
            // Leader should have pushed the timestamp of the first block.
            // In that case there will be only one timestamps in the tmrec.
            //
            // Same holds for any validators that have seen only the first
            // block, which should be starting a new epoch.
            //
            // But in a properly functioning system, we expect many more timestamps
            // in the tmrec list, than merely one.
            //
            let stats = self.compute_mn_sd();
            self.adjusted_complexity(stats.mn)
        } else {
            // Catchall for either protocol misuse, or system startup
            self.adjusted_complexity(self.duration)
        }
    }

    // --------------------------------------------------------
    // Functions called by validator nodes

    pub fn validate_microblock(
        &mut self,
        challenge: &[u8],
        alleged_solution: Option<&[u8]>,
        timestamp: SystemTime,
    ) -> Result<(), InvalidProof> {
        // Validator nodes will call this function to verify a published VDF proof
        // from a micro-block. The complexity level was established at the start of
        // the current epoch.
        //
        // We check that the proof, if present, is valid for the complexity level
        // for this current epoch.
        //
        self.add_timestamp(timestamp);
        match alleged_solution {
            Some(proof) => self.vdf.verify(challenge, self.complexity, proof),
            None => Ok(()),
        }
    }

    pub fn validate_epoch_macroblock(
        &mut self,
        challenge: &[u8],
        alleged_solution: Option<&[u8]>,
        timestamp: SystemTime,
        new_cmplx: u64,
    ) -> Result<(), InvalidProof> {
        // Validator nodes will call this function with the publised VDF proof from
        // a proposed block that begins a new epoch, along with the advertised new
        // complexity level for the next epoch.
        //
        // We check that the VDF proof is valid, and that the next proposed
        // complexity level corresponds to an adjustment from a mean duration that
        // is within 3-sigma bounds of our measured mean inter-block periods.
        //
        self.validate_microblock(challenge, alleged_solution, timestamp)?;
        let stats = self.compute_mn_sd();
        let cmplx_lo = self.adjusted_complexity(stats.mn - 3.0 * stats.sdmn);
        let cmplx_hi = self.adjusted_complexity(stats.mn + 3.0 * stats.sdmn);
        if cmplx_lo <= new_cmplx && new_cmplx <= cmplx_hi {
            Ok(())
        } else {
            // if we disagree with Leader's new complexity level,
            // just leave it alone and continue with what we had.
            Err(InvalidProof)
        }
    }

    // ----------------------------------------------------------
    // internally used functions - should not be called by client code

    fn adjusted_complexity(&self, measured_duration: f32) -> u64 {
        // Compute the complexity level adjusted to meet our
        // expected duration, given a measured duration
        if measured_duration > 0.0 {
            (0.5 + (self.complexity as f32) * self.duration / measured_duration) as u64
        } else {
            self.complexity
        }
    }

    fn compute_mn_sd(&self) -> Stats {
        // analyze the accumulated timestamps for inter-block
        // period statistics.

        let mut tdurs = Vec::<f32>::new();
        let mut wts = Vec::<f32>::new();

        // form vector of inter-block periods
        let mut prev: Option<SystemTime> = None;
        for tm in self.tmrec.clone() {
            match prev {
                None => {
                    prev = Some(tm);
                }
                Some(prev_tm) => {
                    let dur = match tm.duration_since(prev_tm) {
                        Ok(d) => d.as_secs() as f32,
                        _ => 0.0,
                    };
                    tdurs.push(dur);
                    wts.push(1.0);
                    prev = Some(tm);
                }
            }
        }

        // Protect ourselves against too few samples
        // we don't want stupid math errors to kill our running system

        if tdurs.is_empty() {
            // Must have had only 0, 1 timestamps, so we have
            // no inter-block duration samples.
            // Just assume mean equal to our expected duration.
            // Ensure sdmn < mn/3 for later 3-sigma tests
            //
            // This procedure ensures agreement on first block,
            // start of epoch, after initial startup
            //
            return Stats {
                mn: self.duration,
                sd: self.duration,
                sdmn: 0.3 * self.duration,
                twt: 0.0,
            };
        } else {
            // Stetson (iterated) mean and stdev computation
            // to reject outliers gracefully
            let mut sdprev = 0.0;
            let eps = 0.001;
            let mut niter = 0;
            loop {
                let twt = wts.iter().fold(0.0, |tot, wt| tot + wt);
                let mn = wts
                    .iter()
                    .zip(tdurs.iter())
                    .fold(0.0, |sum, (wt, dt)| sum + wt * dt)
                    / twt;
                let deltas: Vec<f32> = tdurs.iter().map(|dt| dt - mn).collect();
                let sd = (wts
                    .iter()
                    .zip(deltas.iter())
                    .fold(0.0, |sum, (wt, delta)| sum + wt * delta * delta)
                    / twt)
                    .sqrt();
                niter += 1;
                if (sd - sdprev).abs() <= eps * sdprev || niter > 100 {
                    // if first sd = 0.0, because of identical durations,
                    // or because we had only one measurement,
                    // we end up here too, since sdprev = 0.0.
                    return Stats {
                        mn,
                        sd,
                        twt, // effective number of contributing measurements
                        sdmn: sd / twt.sqrt(),
                    };
                } else {
                    // Stetson weight adjustment
                    sdprev = sd;
                    let alpha = 2.0;
                    let beta = 2.0;
                    wts.iter_mut().zip(deltas.iter()).for_each(|(pwt, delta)| {
                        *pwt = *pwt / (1.0 + (delta.abs() / (alpha * sd)).powf(beta))
                    });
                }
            }
        }
    }
}

// --------------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use super::*;

    const CORRECT_SOLUTION: &[u8] =
        b"\x00\x52\x71\xe8\xf9\xab\x2e\xb8\xa2\x90\x6e\x85\x1d\xfc\xb5\x54\x2e\x41\x73\xf0\x16\
        \xb8\x5e\x29\xd4\x81\xa1\x08\xdc\x82\xed\x3b\x3f\x97\x93\x7b\x7a\xa8\x24\x80\x11\x38\
        \xd1\x77\x1d\xea\x8d\xae\x2f\x63\x97\xe7\x6a\x80\x61\x3a\xfd\xa3\x0f\x2c\x30\xa3\x4b\
        \x04\x0b\xaa\xaf\xe7\x6d\x57\x07\xd6\x86\x89\x19\x3e\x5d\x21\x18\x33\xb3\x72\xa6\xa4\
        \x59\x1a\xbb\x88\xe2\xe7\xf2\xf5\xa5\xec\x81\x8b\x57\x07\xb8\x6b\x8b\x2c\x49\x5c\xa1\
        \x58\x1c\x17\x91\x68\x50\x9e\x35\x93\xf9\xa1\x68\x79\x62\x0a\x4d\xc4\xe9\x07\xdf\x45\
        \x2e\x8d\xd0\xff\xc4\xf1\x99\x82\x5f\x54\xec\x70\x47\x2c\xc0\x61\xf2\x2e\xb5\x4c\x48\
        \xd6\xaa\x5a\xf3\xea\x37\x5a\x39\x2a\xc7\x72\x94\xe2\xd9\x55\xdd\xe1\xd1\x02\xae\x2a\
        \xce\x49\x42\x93\x49\x2d\x31\xcf\xf2\x19\x44\xa8\xbc\xb4\x60\x89\x93\x06\x5c\x9a\x00\
        \x29\x2e\x8d\x3f\x46\x04\xe7\x46\x5b\x4e\xee\xfb\x49\x4f\x5b\xea\x10\x2d\xb3\x43\xbb\
        \x61\xc5\xa1\x5c\x7b\xdf\x28\x82\x06\x88\x5c\x13\x0f\xa1\xf2\xd8\x6b\xf5\xe4\x63\x4f\
        \xdc\x42\x16\xbc\x16\xef\x7d\xac\x97\x0b\x0e\xe4\x6d\x69\x41\x6f\x9a\x9a\xce\xe6\x51\
        \xd1\x58\xac\x64\x91\x5b";

    #[test]
    #[ignore]
    fn vdf_timing() {
        use std::time::SystemTime;

        let pietrzak_vdf = PietrzakVDFParams(2048).new();
        assert_eq!(
            &pietrzak_vdf.solve(b"\xaa", 100).unwrap()[..],
            CORRECT_SOLUTION
        );
        assert!(pietrzak_vdf.verify(b"\xaa", 100, CORRECT_SOLUTION).is_ok());
        println!("Size of Proof: {}", CORRECT_SOLUTION.len());

        // ---------------------------------

        let niter = 10;
        let start = SystemTime::now();
        for _ in 0..niter {
            pietrzak_vdf.verify(b"\xaa", 100, CORRECT_SOLUTION).is_ok();
        }
        let timing = start.elapsed().unwrap();
        println!("VDF Validate = {:?}", timing / niter);

        // ---------------------------------

        let niter = 1;

        for exp2 in 0..20 {
            let lvl = 1u64 << exp2;
            let niter = 1;

            let start = SystemTime::now();
            for _ in 0..niter {
                pietrzak_vdf.solve(b"\xaa", lvl);
            }
            let timing = start.elapsed().unwrap();
            println!("VDF({}) = {:?}", exp2, timing / niter);
        }
    }
}
