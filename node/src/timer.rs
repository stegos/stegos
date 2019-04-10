//
// MIT License
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
use tokio_timer::clock;
use tokio_timer::Delay;

use futures::{try_ready, Future, Poll, Stream};

use std::time::{Duration, Instant};

/// tokio_timer::Interval implementation, with possibility of reseting deadline;
pub struct Interval {
    delay: Delay,
    duration: Duration,
}

impl Interval {
    /// Create a new `Interval` that starts at `at` and yields every `duration`
    /// interval after that.
    ///
    /// Note that when it starts, it produces item too.
    ///
    /// The `duration` argument must be a non-zero duration.
    ///
    /// # Panics
    ///
    /// This function panics if `duration` is zero.
    pub fn new(at: Instant, duration: Duration) -> Interval {
        assert!(
            duration > Duration::new(0, 0),
            "`duration` must be non-zero."
        );

        Interval::new_with_delay(Delay::new(at), duration)
    }

    /// Creates new `Interval` that yields with interval of `duration`.
    ///
    /// The function is shortcut for `Interval::new(Instant::now() + duration, duration)`.
    ///
    /// The `duration` argument must be a non-zero duration.
    ///
    /// # Panics
    ///
    /// This function panics if `duration` is zero.
    pub fn new_interval(duration: Duration) -> Interval {
        Interval::new(clock::now() + duration, duration)
    }

    pub(crate) fn new_with_delay(delay: Delay, duration: Duration) -> Interval {
        Interval { delay, duration }
    }

    /// Modify interval, to yield with specific interval `duration`.
    pub fn reset(&mut self, duration: Duration) {
        let now = clock::now();
        self.delay.reset(now + duration);
        self.duration = duration;
    }
}

impl Stream for Interval {
    type Item = Instant;
    type Error = tokio_timer::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // Wait for the delay to be done
        let _ = try_ready!(self.delay.poll());

        // Get the `now` by looking at the `delay` deadline
        let now = self.delay.deadline();

        // The next interval value is `duration` after the one that just
        // yielded.
        self.delay.reset(now + self.duration);

        // Return the current instant
        Ok(Some(now).into())
    }
}

#[derive(Debug, Clone)]
pub enum TimerEvents {
    MicroBlockProposeTimer(Instant),
    MicroBlockViewChangeTimer(Instant),
    KeyBlockViewChangeTimer(Instant),
}

/// Checks if interval produce some items.
/// Returns Enum::Variant(Instant).
///
/// Panics if timer return error, or if timer stream is ended.
///
/// Usage:
///  poll_timer!(Enum::Variant => self.timer_field);
#[macro_export]
macro_rules! poll_timer {
    ($($map: ident)::* => $($timer: tt)*) => {
    let err_msg = concat!("error when polling timer ", stringify!($($timer)*));
    let empty_msg = concat!("timer suddenly ends ", stringify!($($timer)*));
        match $($timer)*.poll().expect(err_msg) {
            Async::Ready(x) => return Async::Ready($($map)::*(x.expect(empty_msg))),
            Async::NotReady => {}
        }
    }
}
