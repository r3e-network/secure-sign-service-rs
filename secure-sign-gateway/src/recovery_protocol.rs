//! Versioned recovery metadata emitted by the signing gateway.
//!
//! This is intentionally a signing-domain protocol. It is not a transaction
//! outcome and must be mapped by the submitting service only after the
//! identical request digest has been reconciled.

pub const PROTOCOL: &str = "neoos.signing-recovery";
pub const VERSION: u16 = 1;
pub const OUTCOME_HEADER: &str = "x-signing-outcome";
pub const DIGEST_HEADER: &str = "x-signing-digest";
pub const PROTOCOL_HEADER: &str = "x-signing-protocol";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryOutcome {
    Unknown,
    CommitPending,
    Conflict,
    InvalidEnclaveResult,
}

impl RecoveryOutcome {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Unknown => "signing-outcome-unknown",
            Self::CommitPending => "result-commit-pending",
            Self::Conflict => "result-conflict",
            Self::InvalidEnclaveResult => "invalid-enclave-result",
        }
    }

    pub const fn retry_identical_digest(self) -> bool {
        matches!(self, Self::Unknown | Self::CommitPending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_values_are_stable_and_domain_specific() {
        assert_eq!(PROTOCOL, "neoos.signing-recovery");
        assert_eq!(VERSION, 1);
        assert_eq!(RecoveryOutcome::Unknown.wire(), "signing-outcome-unknown");
        assert_eq!(
            RecoveryOutcome::CommitPending.wire(),
            "result-commit-pending"
        );
        assert_eq!(RecoveryOutcome::Conflict.wire(), "result-conflict");
        assert_eq!(
            RecoveryOutcome::InvalidEnclaveResult.wire(),
            "invalid-enclave-result"
        );
        assert!(RecoveryOutcome::Unknown.retry_identical_digest());
        assert!(RecoveryOutcome::CommitPending.retry_identical_digest());
        assert!(!RecoveryOutcome::Conflict.retry_identical_digest());
        assert!(!RecoveryOutcome::InvalidEnclaveResult.retry_identical_digest());
    }
}
