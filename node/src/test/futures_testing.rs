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

use futures::executor::{with_notify, Notify};
use futures::{lazy, Async};
use log::debug;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;
use tokio_executor::park::{Park, Unpark};
use tokio_timer::{
    self,
    clock::{self, Now},
    timer::Timer,
};

/// helper type that allows multiple polling of task in test, if notify was called.
pub struct NodeNotify {
    pub repeat_poll: Mutex<bool>,
}

impl NodeNotify {
    fn reset(&self) {
        *self.repeat_poll.lock().unwrap() = false;
    }

    fn set(&self) {
        *self.repeat_poll.lock().unwrap() = true;
    }

    fn is_set(&self) -> bool {
        *self.repeat_poll.lock().unwrap()
    }

    /// Call internal routine, and ignore any notifications,
    /// if any was set during internal routine.
    ///
    /// Some times testing framework need to create internal channels,
    /// or futures, which notify event should be ignored.
    pub fn internal_routine<F: FnMut()>(&self, mut routine: F) {
        let flag = self.is_set();
        debug!("Calling internal routing, flag = {}", flag);
        routine();
        *self.repeat_poll.lock().unwrap() = flag;
    }
}

impl Notify for NodeNotify {
    fn notify(&self, _: usize) {
        self.set()
    }
}

/// execute poll fn as may times as it needs.
pub fn execute<U, E, F: FnMut(&NodeNotify) -> Result<Async<U>, E>>(msg: String, mut future: F)
where
    U: Debug + Eq,
    E: Debug + Eq,
{
    let ref node_notify = Arc::new(NodeNotify {
        repeat_poll: Mutex::new(false),
    });

    super::logger::MODULE_PREFIX.with(|n| *n.borrow_mut() = msg);
    with_notify(node_notify, 1, || loop {
        assert_eq!(future(&node_notify), Ok(Async::NotReady));
        if !node_notify.is_set() {
            break;
        }
        debug!("POLL ONCE MORE");
        node_notify.reset();
    });

    super::logger::MODULE_PREFIX.with(|n| *n.borrow_mut() = "TESTING".to_string());
}

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
    use assert_matches::assert_matches;
    use futures::Future;
    start_test(|timer| {
        let clock = clock::now();
        let deadline = clock + Duration::from_millis(1000);
        let mut delay = tokio_timer::Delay::new(deadline);
        assert_matches!(delay.poll(), Ok(Async::NotReady));
        wait(timer, Duration::from_millis(1000));
        assert_matches!(delay.poll(), Ok(Async::Ready(())));
    })
}
