//! Timing utilities for performance measurements.
//!
//! This module provides an RAII timer pattern that automatically records
//! elapsed time when dropped, useful for measuring phase durations in
//! evaluation pipelines.

use std::time::{Duration, Instant};

/// RAII timer that records elapsed time to a mutable slot on Drop.
///
/// This timer starts when created and automatically accumulates the elapsed
/// time to the provided `Duration` slot when it is dropped. This pattern
/// ensures timing is always recorded, even if execution exits early via
/// panic or return.
///
/// # Example
///
/// ```rust,ignore
/// use std::time::Duration;
/// let mut total = Duration::ZERO;
/// {
///     let _timer = PhaseTimer::new(&mut total);
///     // ... work being measured ...
/// } // timer is dropped here, total is updated
/// ```
pub struct PhaseTimer<'a> {
    start: Instant,
    slot: &'a mut Duration,
}

impl<'a> PhaseTimer<'a> {
    /// Create a new timer that will accumulate elapsed time to `slot`.
    pub fn new(slot: &'a mut Duration) -> Self {
        Self {
            start: Instant::now(),
            slot,
        }
    }
}

impl Drop for PhaseTimer<'_> {
    fn drop(&mut self) {
        *self.slot += self.start.elapsed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_phase_timer_records_elapsed() {
        let mut duration = Duration::ZERO;
        {
            let _timer = PhaseTimer::new(&mut duration);
            thread::sleep(Duration::from_millis(10));
        }
        assert!(duration.as_millis() >= 10);
    }

    #[test]
    fn test_phase_timer_accumulates() {
        let mut duration = Duration::ZERO;
        for _ in 0..3 {
            {
                let _timer = PhaseTimer::new(&mut duration);
                thread::sleep(Duration::from_millis(5));
            }
        }
        assert!(duration.as_millis() >= 15);
    }
}
