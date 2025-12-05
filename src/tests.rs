#[cfg(test)]
mod tests {
    use crate::caserver::CAServer;
    use crate::certificate::Certificate;
    use crate::ca::CertificateAuthority;
    use crate::caclient::CAClient;
    use crate::errors::{CaServerError, CaClientError};

    #[test]
    fn test_certificate_authority_creation() -> Result<(), CaServerError> {
        let ca = CertificateAuthority::new();
        
        // Test that keys are generated
        let _ca_private_key = ca.private_key_bytes()?;
        let _ca_public_key = ca.public_key_bytes()?;
        
        Ok(())
    }

    #[test]
    fn test_certificate_signing_and_verification() -> Result<(), CaServerError> {
        let caserver = CAServer::new();

        // Create a sample certificate
        let mut cert = Certificate {
            identity: "test_user".as_bytes().to_vec(),
            public_key: "user_public_key".to_string(),
            permissions: vec!["read".to_string(), "write".to_string()],
            expiry: 99999999999,
            signature: None,
        };

        // Sign the certificate
        caserver.sign(&mut cert)?;

        // Verify the certificate
        let is_valid = caserver.verify(&cert)?;
        assert!(is_valid, "Certificate should be valid after signing");

        Ok(())
    }

    #[test]
    fn test_tampered_certificate_verification() -> Result<(), CaServerError> {
        let caserver = CAServer::new();
        let ca = CertificateAuthority::new();

        // Create and sign a certificate
        let mut cert = Certificate {
            identity: "test_user".as_bytes().to_vec(),
            public_key: "user_public_key".to_string(),
            permissions: vec!["read".to_string(), "write".to_string()],
            expiry: 99999999999,
            signature: None,
        };

        caserver.sign(&mut cert)?;

        // Tamper with the certificate by removing signature
        let mut tampered_cert = cert.clone();
        tampered_cert.signature = None;
        
        let is_tampered_valid = caserver.verify(&tampered_cert).unwrap_or(false);
        assert!(!is_tampered_valid, "Tampered certificate should not be valid");

        Ok(())
    }

    #[test]
    fn test_certificate_with_different_ca() -> Result<(), CaServerError> {
        let caserver1 = CAServer::new();
        let caserver2 = CAServer::new();

        // Create and sign certificate with ca1
        let mut cert = Certificate {
            identity: "test_user".as_bytes().to_vec(),
            public_key: "user_public_key".to_string(),
            permissions: vec!["read".to_string(), "write".to_string()],
            expiry: 99999999999,
            signature: None,
        };

        caserver1.sign(&mut cert)?;

        // Try to verify with ca2 (should fail)
        let is_invalid_key_valid = caserver2.verify(&cert).unwrap_or(false);
        assert!(!is_invalid_key_valid, "Certificate should not be valid when verified with different CA");

        Ok(())
    }

    #[test]
    fn test_private_key_access() -> Result<(), CaServerError> {
        let ca = CertificateAuthority::new();
        
        // Test safe private key access
        let private_key = ca.get_private_key()?;
        let _public_key = ca.public_key.as_ref().ok_or(CaServerError::Other("CA public key not set".to_string()))?;
        
        // The private key should be accessible through the safe method
        let private_key_bytes = ca.private_key_bytes()?;
        assert!(private_key_bytes.len() > 0, "Private key should have bytes");
        
        Ok(())
    }

    #[test]
    fn test_caclient_creation() -> Result<(), CaClientError> {
        let client = CAClient::new();
        
        // Test that keys are generated
        let _ca_private_key = client.private_key_bytes()?;
        let _ca_public_key = client.public_key_bytes()?;
        
        Ok(())
    }

    #[test]
    fn test_caclient_verify_no_certs() {
        let client = CAClient::new();
        let public_key = "test_key".as_bytes().to_vec();
        
        // Should fail when no certificates are initialized
        let result = client.verify(public_key);
        assert!(result.is_err(), "Should fail when no certificates are initialized");
        assert!(matches!(result.unwrap_err(), CaClientError::NoCertsInitialized), "Should return NoCertsInitialized error");
    }

    #[test]
    fn test_caclient_verify_missing_cert() {
        let mut client = CAClient::new();
        let public_key = "nonexistent_key".as_bytes().to_vec();
        
        // Initialize empty certificates map
        client.initialize_certs();
        
        // Should fail when certificate is missing
        let result = client.verify(public_key);
        assert!(result.is_err(), "Should fail when certificate is missing");
        assert!(matches!(result.unwrap_err(), CaClientError::MissingCert), "Should return MissingCert error");
    }

    #[test]
    fn test_caclient_verify_valid_cert() -> Result<(), CaClientError> {
        let mut client = CAClient::new();
        
        // Create and sign a certificate
        let mut cert = Certificate {
            identity: "test_user".as_bytes().to_vec(),
            public_key: "user_public_key".to_string(),
            permissions: vec!["read".to_string(), "write".to_string()],
            expiry: 99999999999,
            signature: None,
        };
        
        client.ca.sign(&mut cert).map_err(CaClientError::from)?;
        
        // Add certificate to client's cert store
        client.add_certificate("user_public_key".as_bytes().to_vec(), cert);
        
        // Should successfully verify the certificate
        let public_key = "user_public_key".as_bytes().to_vec();
        let is_valid = client.verify(public_key)?;
        assert!(is_valid, "Certificate should be valid");
        
        Ok(())
    }

    #[test]
    fn test_caclient_verify_invalid_cert() -> Result<(), CaClientError> {
        let mut client = CAClient::new();
        
        // Create a certificate without signing it
        let cert = Certificate {
            identity: "test_user".as_bytes().to_vec(),
            public_key: "user_public_key".to_string(),
            permissions: vec!["read".to_string(), "write".to_string()],
            expiry: 99999999999,
            signature: None, // No signature
        };
        
        // Add unsigned certificate to client's cert store
        client.add_certificate("user_public_key".as_bytes().to_vec(), cert);
        
        // Should fail to verify the unsigned certificate
        let public_key = "user_public_key".as_bytes().to_vec();
        let result = client.verify(public_key);
        assert!(result.is_err(), "Should fail to verify unsigned certificate");
        
        Ok(())
    }

    #[test]
    fn test_caclient_multiple_certs() -> Result<(), CaClientError> {
        let mut client = CAClient::new();
        
        // Create and sign multiple certificates
        let mut cert1 = Certificate {
            identity: "user1".as_bytes().to_vec(),
            public_key: "user1_public_key".to_string(),
            permissions: vec!["read".to_string()],
            expiry: 99999999999,
            signature: None,
        };
        
        let mut cert2 = Certificate {
            identity: "user2".as_bytes().to_vec(),
            public_key: "user2_public_key".to_string(),
            permissions: vec!["write".to_string()],
            expiry: 99999999999,
            signature: None,
        };
        
        client.ca.sign(&mut cert1).map_err(CaClientError::from)?;
        client.ca.sign(&mut cert2).map_err(CaClientError::from)?;
        
        // Add both certificates to client's cert store
        client.add_certificate("user1_public_key".as_bytes().to_vec(), cert1);
        client.add_certificate("user2_public_key".as_bytes().to_vec(), cert2);
        
        // Should verify both certificates successfully
        let is_valid1 = client.verify("user1_public_key".as_bytes().to_vec())?;
        let is_valid2 = client.verify("user2_public_key".as_bytes().to_vec())?;
        
        assert!(is_valid1, "First certificate should be valid");
        assert!(is_valid2, "Second certificate should be valid");
        
        Ok(())
    }
}
