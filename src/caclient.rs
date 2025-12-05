use crate::ca::CertificateAuthority;
use crate::certificate::Certificate;
use crate::errors::*;
use rand::thread_rng;
use schnorr_rs::*;
use schnorr_rs::*;
use serde_json;
use sha2::Sha256;
use std::collections::HashMap;

pub struct CAClient {
    pub ca: CertificateAuthority,
    hostname: String,
    ip: String,
    port: u16,
    certs: Option<HashMap<Vec<u8>, Certificate>>,
}

impl Default for CAClient {
    fn default() -> Self {
        CAClient {
            ca: CertificateAuthority::default(),
            hostname: String::from("localhost"),
            ip: String::from("128.0.0.1"),
            port: 5555,
            certs: None,
        }
    }
}

impl CAClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn private_key_bytes(&self) -> Result<Vec<u8>, CaError> {
        self.ca.private_key_bytes()
    }

    pub fn public_key_bytes(&self) -> Result<Vec<u8>, CaError> {
        self.ca.public_key_bytes()
    }

    fn get_cert(&self, public_key: &Vec<u8>) -> Result<&Certificate, CaClientError> {
        match &self.certs {
            Some(certs) => match certs.get(public_key) {
                Some(cert) => Ok(cert),
                None => Err(CaClientError::MissingCert),
            },
            None => Err(CaClientError::NoCertsInitialized),
        }
    }

    pub fn verify(&self, public_key: Vec<u8>) -> Result<bool, CaClientError> {
        let cert = self.get_cert(&public_key)?;
        self.ca.verify(cert).map_err(CaClientError::from)
    }

    pub fn add_certificate(&mut self, public_key: Vec<u8>, cert: Certificate) {
        if self.certs.is_none() {
            self.certs = Some(HashMap::new());
        }
        self.certs.as_mut().unwrap().insert(public_key, cert);
    }

    pub fn initialize_certs(&mut self) {
        self.certs = Some(HashMap::new());
    }
}
