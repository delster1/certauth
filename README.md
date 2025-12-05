### authentication - rust
- zero-trust auth with schnorr-based mutual authentication
- non-interactive schnorr, using (u,c,z) to sign certificates in server
	- certs:
		- identity / hostname
		-  perms
		- expiration
		- signature
- stateless CA, just receives cert and verifies
- verification - client sends:
    - certificate - signed by CA
    - schnorr proof for cert's public key
- verification - server responds:
    - verifies schnorr proof 
    - verifies certificate
    - sends server certificate
    - maybe issues session key? 
- final verification - client recieves
    - schnorr proof success
    - certificate success
    - server cert - performs verification
- re-issue cert
    - on cert expired, return to sender cert expired
    - cancel entire auth procedure on sender & reciever
    - sender asks for new cert from CA
    - upon success, retry!
towrite:
-  CA:
    - private/public keygen
    - schnorr proof - verify signature
    - certs:
        - structure
            - yaml
                {
                    identity: "minipc",
                    public_key: H_minipc,
                    permissions: ["status:publish"],
                    expiry: 1730000000,
                    cert_signature: (u_cert, c_cert, z_cert)   // signed by CA key
                }
        - creation
        - re-issue 
        - issue
        - sign 
        - send/recieve
-  Clients (API server & clients):
    - schnorr proof - verify reciever 
    - private/public keygen
    - request new cert 
    - send cert
    - verification & denial
	- long-lived sessions & session key
    

