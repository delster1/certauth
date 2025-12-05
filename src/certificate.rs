use schnorr_rs::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::errors::CaError;

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("")
         .field(&self.identity)
         .field(&self.public_key)
         .field(&self.permissions)
         .field(&self.expiry)
        .field(&"signature")
         .finish()
    }
}

impl Default for Certificate {
    fn default() -> Self {
        
        Certificate {
            identity: "test_user".as_bytes().to_vec(),
            public_key: "user_public_key".to_string(),
            permissions: vec!["read".to_string(), "write".to_string()],
            expiry: 99999999999,
            signature: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Certificate {
    pub identity: Vec<u8>,
    pub public_key: String,
    pub permissions: Vec<String>,
    pub expiry: u64,
    pub signature: Option<Signature<SchnorrGroup>>,
}

impl Certificate {
    pub fn get_hash(&self) -> Result<Vec<u8>, CaError> {
        let mut cert_clone = self.clone();
        cert_clone.signature = None;
        let cert_bytes = serde_json::to_vec(&cert_clone).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&cert_bytes);
        Ok(hasher.finalize().to_vec())
    }
}
