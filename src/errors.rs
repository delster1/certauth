use thiserror::Error;

#[derive(Error, Debug)]
pub enum CaServerError {
    #[error("CA error: {0}")]
    Ca(#[from] CaError),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Other server error: {0}")]
    Other(String),
}

#[derive(Error, Debug)]
pub enum CaError {
    #[error("Certificate verification failed")]
    InvalidCertificate,

    #[error("Missing Public Key")]
    MissingPublicKey,

    #[error("Missing Private Key")]
    MissingPrivateKey,

    #[error("Certificate expired")]
    CertificateExpired,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Other error: {0}")]
    Other(String),
}
#[derive(Error, Debug)]
pub enum CaClientError {
    #[error("CA error: {0}")]
    Ca(#[from] CaError),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Invalid server response")]
    InvalidResponse,

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Certificate cannot be found")]
    MissingCert,

    #[error("No certificates have been created")]
    NoCertsInitialized,

    #[error("Verification failed for certificate")]
    CertVerificationFailed,

    #[error("Other client error: {0}")]
    Other(String),
}

