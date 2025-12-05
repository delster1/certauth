use crate::{certificate::Certificate, errors::CaError};
use rand::thread_rng;
use schnorr_rs::*;
use serde_json;
use sha2::Sha256;
use crate::errors::CaServerError;

pub struct CertificateAuthority {
    pub scheme: SignatureScheme<SchnorrGroup, sha2::Sha256>,
    private_key: Option<SigningKey<SchnorrGroup>>,
    pub public_key: Option<PublicKey<SchnorrGroup>>,
}

impl Default for CertificateAuthority {
    fn default() -> Self {
        let mut rng = thread_rng();
        let scheme = schnorr_rs::signature_scheme::<Sha256>("1623299", "811649", "1109409")
                .expect("scheme");
        let (private_key, public_key) = scheme.generate_key(&mut rng);

        CertificateAuthority {
            scheme,
            private_key : Some(private_key),
            public_key : Some(public_key) 
        }
    }
}

impl CertificateAuthority {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn get_private_key(&self) -> Result<&SigningKey<SchnorrGroup>, CaError> {
        self.private_key.as_ref().ok_or(CaError::MissingPrivateKey)
    }

    pub fn private_key_bytes(&self) -> Result<Vec<u8>, CaError> {
        let private_key = self.get_private_key()?;
        Ok(serde_json::to_vec(private_key)?)
    }

    pub fn public_key_bytes(&self) -> Result<Vec<u8>, CaError> {
        let public_key = self.public_key.as_ref().ok_or(CaError::MissingPublicKey)?;
        Ok(serde_json::to_vec(public_key)?)
    }

    pub fn sign(&self, cert: &mut Certificate) -> Result<(), CaError> {
        let mut rng = thread_rng();
        let cert_hash = cert.get_hash()?;
        let private_key = self.get_private_key()?;
        let public_key = self
            .public_key
            .as_ref()
            .ok_or(CaError::MissingPublicKey)?;
        let signature = self
            .scheme
            .sign(&mut rng, private_key, public_key, cert_hash);
        cert.signature = Some(signature);
        Ok(())
    }

    pub fn verify(&self, cert: &Certificate) -> Result<bool, CaError> {
        let cert_hash = cert.get_hash()?;
        let public_key = self.public_key.as_ref().ok_or(CaError::Other("CA public key not set".to_string()))?;
        let signature = cert.signature.as_ref().ok_or(CaError::InvalidSignature)?;
        Ok(self.scheme.verify(public_key, &cert_hash, signature))
    }
}
