use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid contract ID: {0}")]
    InvalidContractId(String),

    #[error("challenge not found")]
    ChallengeNotFound,

    #[error("challenge expired")]
    ChallengeExpired,

    #[error("storage error: {0}")]
    Storage(String),

    #[error("invalid authenticator data: {0}")]
    InvalidAuthenticatorData(String),

    #[error("invalid client data: {0}")]
    InvalidClientData(String),

    #[error("RP ID mismatch")]
    RpIdMismatch,

    #[error("user presence flag not set")]
    UserNotPresent,

    #[error("challenge mismatch")]
    ChallengeMismatch,

    #[error("origin mismatch: expected {expected}, got {actual}")]
    OriginMismatch { expected: String, actual: String },

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
