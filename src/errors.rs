//! Collection of errors and falurest in the proof system.

use ark_std::fmt;

/// Error identifying a failure in the proof verification.
#[derive(Debug, Clone)]
pub struct VerificationError;

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Verification Error.")
    }
}

/// Verification result.
pub type VerificationResult = ark_std::result::Result<(), VerificationError>;
