use std::time::{Duration, Instant};

/// Tracks heartbeat send/receive times and determines connection health.
pub struct Heartbeat {
    interval: Duration,
    last_sent: Instant,
    last_recv: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatState {
    Healthy,
    Suspect,
    Timeout,
}

impl Heartbeat {
    /// Create a new heartbeat tracker with the specified interval.
    pub fn new(interval: Duration, now: Instant) -> Self {
        Self {
            interval,
            last_sent: now,
            last_recv: now,
        }
    }

    /// Record that a heartbeat frame was sent at `now`.
    pub fn mark_sent(&mut self, now: Instant) {
        self.last_sent = now;
    }

    /// Record that a heartbeat frame was received at `now`.
    pub fn mark_recv(&mut self, now: Instant) {
        self.last_recv = now;
    }

    /// Whether it's time to send another heartbeat.
    pub fn should_send(&self, now: Instant) -> bool {
        now.duration_since(self.last_sent) >= self.interval
    }

    /// Determine current state based on time since last receive.
    pub fn state(&self, now: Instant) -> HeartbeatState {
        let since = now.duration_since(self.last_recv);
        if since >= self.interval * 5 {
            HeartbeatState::Timeout
        } else if since >= self.interval * 3 {
            HeartbeatState::Suspect
        } else {
            HeartbeatState::Healthy
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_state_progression() {
        let start = Instant::now();
        let hb = Heartbeat::new(Duration::from_secs(5), start);
        assert_eq!(hb.state(start), HeartbeatState::Healthy);

        let t = start + Duration::from_secs(16); // >3*5
        assert_eq!(hb.state(t), HeartbeatState::Suspect);

        let t = start + Duration::from_secs(26); // >5*5
        assert_eq!(hb.state(t), HeartbeatState::Timeout);
    }
}

