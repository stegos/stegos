//! Timestamp.

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

use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use failure::Error;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use stegos_crypto::hash::{Hashable, Hasher};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const UNIX_EPOCH: Timestamp = Timestamp(0);

    pub fn now() -> Self {
        let timestamp = SystemTime::now();
        timestamp.into()
    }

    /// Returns `Some(t)` where `t` is the time `self + duration` if `t` can be represented as
    /// `Timestamp` (which means it's inside the bounds of the underlying data structure), `None`
    /// otherwise.
    pub fn checked_add(&self, duration: Duration) -> Option<Timestamp> {
        let duration = duration.as_secs() * 1_000_000_000u64 + duration.subsec_nanos() as u64;
        self.0.checked_add(duration).map(Timestamp)
    }

    /// Returns `Some(t)` where `t` is the time `self - duration` if `t` can be represented as
    /// `Timestamp` (which means it's inside the bounds of the underlying data structure), `None`
    /// otherwise.
    pub fn checked_sub(&self, duration: Duration) -> Option<Timestamp> {
        let duration = duration.as_secs() * 1_000_000_000u64 + duration.subsec_nanos() as u64;
        self.0.checked_sub(duration).map(Timestamp)
    }

    /// Returns the amount of time elapsed from an earlier point in time.
    ///
    pub fn duration_since(&self, earlier: Timestamp) -> Duration {
        assert!(earlier.0 <= self.0);
        let duration = self.0 - earlier.0;
        Duration::from_nanos(duration)
    }

    ///
    /// Returns an ISO 8601/RFC 3339 date and time string such as 1996-12-19T16:39:57-08:00.123Z
    ///
    pub fn format_rfc3339(&self) -> String {
        let secs = (self.0 / 1_000_000_000) as i64;
        let nsecs = (self.0 % 1_000_000_000) as u32;
        let dt = Utc.timestamp(secs, nsecs);
        dt.to_rfc3339_opts(SecondsFormat::Nanos, true)
    }

    /// Parses ISO 8601/RFC 3339 date and time string such as `1996-12-19T16:39:57-08:00Z`,
    /// then returns a new `Timestamp`.
    pub fn parse_rfc3339(s: &str) -> Result<Timestamp, Error> {
        let dt = DateTime::parse_from_rfc3339(s)?;
        let timestamp = dt.timestamp_nanos() as u64;
        Ok(timestamp.into())
    }
}

impl From<u64> for Timestamp {
    fn from(timestamp: u64) -> Self {
        Timestamp(timestamp)
    }
}

impl Into<u64> for Timestamp {
    fn into(self) -> u64 {
        self.0
    }
}

impl From<i64> for Timestamp {
    fn from(timestamp: i64) -> Self {
        Timestamp(timestamp as u64)
    }
}

impl Into<i64> for Timestamp {
    fn into(self) -> i64 {
        self.0 as i64
    }
}

impl From<f64> for Timestamp {
    fn from(timestamp: f64) -> Self {
        Timestamp((timestamp * 1e9).round() as u64)
    }
}

impl Into<f64> for Timestamp {
    fn into(self) -> f64 {
        self.0 as f64 / 1e9
    }
}

impl From<SystemTime> for Timestamp {
    fn from(timestamp: SystemTime) -> Self {
        let since_the_epoch = timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time is valid");
        let timestamp =
            since_the_epoch.as_secs() * 1_000_000_000u64 + since_the_epoch.subsec_nanos() as u64;
        Timestamp(timestamp)
    }
}

impl Into<SystemTime> for Timestamp {
    fn into(self) -> SystemTime {
        UNIX_EPOCH + Duration::from_nanos(self.0)
    }
}

impl Add<Duration> for Timestamp {
    type Output = Timestamp;

    /// # Panics
    ///
    /// This function may panic if the resulting point in time cannot be represented by the
    /// underlying data structure. See [`checked_add`] for a version without panic.
    ///
    fn add(self, dur: Duration) -> Timestamp {
        self.checked_add(dur)
            .expect("overflow when adding duration to instant")
    }
}

impl AddAssign<Duration> for Timestamp {
    fn add_assign(&mut self, other: Duration) {
        *self = *self + other;
    }
}

impl Sub<Duration> for Timestamp {
    type Output = Timestamp;

    fn sub(self, dur: Duration) -> Timestamp {
        self.checked_sub(dur)
            .expect("overflow when subtracting duration from instant")
    }
}

impl SubAssign<Duration> for Timestamp {
    fn sub_assign(&mut self, other: Duration) {
        *self = *self - other;
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_rfc3339())
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_rfc3339())
    }
}

impl Hashable for Timestamp {
    fn hash(&self, state: &mut Hasher) {
        self.0.hash(state);
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.format_rfc3339())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Timestamp, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Timestamp::parse_rfc3339(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::Timestamp;
    use serde_test::{assert_tokens, Token};

    #[test]
    fn serde() {
        // check deserialization with millis precision.
        let timestamp: Timestamp = 1560850195_123456789u64.into();
        assert_tokens(&timestamp, &[Token::Str("2019-06-18T09:29:55.123456789Z")]);
        let timestamp_str = serde_json::to_string(&timestamp).unwrap();
        let timestamp_new: Timestamp = serde_json::from_str(&timestamp_str).unwrap();
        assert_eq!(timestamp, timestamp_new)
    }
}
