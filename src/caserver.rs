use crate::ca::CertificateAuthority;
use crate::certificate::Certificate;
use crate::errors::{CaError,CaServerError};
use rand::thread_rng;
use schnorr_rs::*;
use serde_json;
use sha2::Sha256;

pub struct CAServer {
    pub ca: CertificateAuthority,
    hostname: String,
    ip: String,
    port: u16,
}

impl Default for CAServer {
    fn default() -> Self {
        CAServer {
            ca: CertificateAuthority::default(),
            hostname: String::from("localhost"),
            ip: String::from("128.0.0.1"),
            port: 5555,
        }
    }
}

impl CAServer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn private_key_bytes(&self) -> Result<Vec<u8>,CaError> {
        self.ca.private_key_bytes()
    }

    pub fn public_key_bytes(&self) -> Result<Vec<u8>,CaError> {
        self.ca.public_key_bytes()
    }

    pub fn verify(&self, cert:&Certificate) -> Result<bool, CaError> {
        self.ca.verify(cert)
    }

    pub fn sign(&self, cert: &mut Certificate) -> Result<(), CaServerError> {
        let mut rng = thread_rng();
        let cert_hash = cert.get_hash()?;
        let private_key = self.ca.get_private_key()?;
        let public_key = self
            .ca
            .public_key
            .as_ref()
            .ok_or(CaError::MissingPublicKey.to_string());
        let signature = self
            .ca
            .scheme
            .sign(&mut rng, private_key, public_key.unwrap(), cert_hash);
        cert.signature = Some(signature);
        Ok(())
    }

    pub fn issue_certificate(
        &self,
        identity: Vec<u8>,
        public_key: String,
        permissions: Vec<String>,
        expiry: u64,
    ) -> Result<Certificate, CaServerError> {
        let mut cert = Certificate {
            identity,
            public_key,
            permissions,
            expiry,
            signature: None,
        };
        self.sign(&mut cert)?;
        Ok(cert)
    }
}
