use std::time::{Duration, Instant};

use chrono::Utc;
use tonic::{metadata::MetadataMap, Status};

#[derive(Clone, Copy)]
pub(crate) struct Budget {
    pub(crate) deadline: Instant,
}

impl Budget {
    pub(crate) fn new(timeout: Duration, metadata: &MetadataMap) -> Result<Self, Status> {
        let timeout = match metadata.get("grpc-timeout") {
            Some(raw) => timeout
                .min(parse_timeout(raw.to_str().map_err(|_| {
                    Status::invalid_argument("invalid grpc-timeout")
                })?)?),
            None => timeout,
        };
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| Status::invalid_argument("signing timeout out of range"))?;
        Ok(Self { deadline })
    }

    pub(crate) fn with_expiry(mut self, not_after: i64) -> Result<Self, Status> {
        Self::check_expiry(not_after)?;
        let remaining_ms =
            i128::from(not_after) * 1_000 - i128::from(Utc::now().timestamp_millis());
        if remaining_ms <= 0 {
            return Err(Status::deadline_exceeded("request expired before signing"));
        }
        let millis = u64::try_from(remaining_ms)
            .map_err(|_| Status::invalid_argument("request expiry out of range"))?;
        if let Some(expiry) = Instant::now().checked_add(Duration::from_millis(millis)) {
            self.deadline = self.deadline.min(expiry);
        }
        self.remaining()?;
        Ok(self)
    }

    pub(crate) fn check_expiry(not_after: i64) -> Result<(), Status> {
        if not_after <= Utc::now().timestamp() {
            return Err(Status::deadline_exceeded("request expired before signing"));
        }
        Ok(())
    }

    pub(crate) fn remaining(self) -> Result<Duration, Status> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| Status::deadline_exceeded("signing request deadline exceeded"))
    }
}

fn parse_timeout(value: &str) -> Result<Duration, Status> {
    let invalid = || Status::invalid_argument("invalid grpc-timeout");
    if value.len() < 2 || value.len() > 9 || !value.is_ascii() {
        return Err(invalid());
    }
    let (digits, unit) = value.split_at(value.len() - 1);
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    let n = digits.parse::<u64>().map_err(|_| invalid())?;
    Ok(match unit {
        "H" => Duration::from_secs(n * 3_600),
        "M" => Duration::from_secs(n * 60),
        "S" => Duration::from_secs(n),
        "m" => Duration::from_millis(n),
        "u" => Duration::from_micros(n),
        "n" => Duration::from_nanos(n),
        _ => return Err(invalid()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_deadline_can_only_shorten_the_server_budget() {
        let mut metadata = MetadataMap::new();
        metadata.insert("grpc-timeout", "5m".parse().unwrap());
        assert!(
            Budget::new(Duration::from_secs(1), &metadata)
                .unwrap()
                .remaining()
                .unwrap()
                <= Duration::from_millis(5)
        );
        metadata.insert("grpc-timeout", "5S".parse().unwrap());
        assert!(
            Budget::new(Duration::from_millis(10), &metadata)
                .unwrap()
                .remaining()
                .unwrap()
                <= Duration::from_millis(10)
        );
        for invalid in ["", "123456789S", "-1S", "3x", "1.5S"] {
            assert!(parse_timeout(invalid).is_err());
        }
    }
}
