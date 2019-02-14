//
// Copyright (c) 2019 Stegos
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

use assert_matches::assert_matches;
use futures::{lazy, Async, Future};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;
use tokio_executor::park::{Park, Unpark};
use tokio_timer::{
    self,
    clock::{self, Now},
    timer::Timer,
};

#[derive(Clone, Debug)]
pub struct TestTimer {
    current_time: Arc<Mutex<Instant>>,
}

impl TestTimer {
    fn new() -> Self {
        TestTimer {
            current_time: Arc::new(Mutex::new(Instant::now())),
        }
    }
    fn advance(&self, duration: Duration) {
        *self.current_time.lock().unwrap() += duration;
    }
}

impl Park for TestTimer {
    type Unpark = Self;
    type Error = ();

    fn unpark(&self) -> Self::Unpark {
        self.clone()
    }

    fn park(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn park_timeout(&mut self, _: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Unpark for TestTimer {
    fn unpark(&self) {}
}

impl Now for TestTimer {
    fn now(&self) -> Instant {
        *self.current_time.lock().unwrap()
    }
}

/// Init test clocks, and run test.
pub fn start_test<F: FnOnce(&mut Timer<TestTimer>)>(func: F) {
    let time = TestTimer::new();
    let clock = clock::Clock::new_with_now(time.clone());

    let mut enter = tokio_executor::enter().unwrap();
    clock::with_default(&clock, &mut enter, |enter| {
        let mut timer = Timer::new(time);
        let handle = timer.handle();
        tokio_timer::with_default(&handle, enter, |enter| {
            enter
                .block_on(lazy(|| {
                    func(&mut timer);
                    futures::done(Ok::<(), ()>(()))
                }))
                .unwrap()
        })
    })
}

/// Emulate time in tests
pub fn wait(timer: &mut Timer<TestTimer>, duration: Duration) {
    timer.get_park().advance(duration);
    timer.turn(None).unwrap();
}

#[test]
fn test_timer() {
    start_test(|timer| {
        let clock = clock::now();
        let deadline = clock + Duration::from_millis(1000);
        let mut delay = tokio_timer::Delay::new(deadline);
        assert_matches!(delay.poll(), Ok(Async::NotReady));
        wait(timer, Duration::from_millis(1000));
        assert_matches!(delay.poll(), Ok(Async::Ready(())));
    })
}
