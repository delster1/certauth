### authentication - rust
- zero-trust auth with schnorr-based mutual authentication
- interactive schnorr to challenge knowledge of CA secret on each cert request
	- certs:
		- identity / hostname
		-  perms
		- expiration
		- signature
		- schnorr challenge
- stateless CA, just receives cert and verifies
- Certs:
  	- Schnorr proof to verify rotating secret performed by both clients
  - CA:
  	- generates `sk_CA=x`, `pk_CA=g^x`
    - issues `Cert_S` for a service `S` given `pk_S` and `sid_S`
  - clients `C`:
    - given `sk_C` and `cert_C` and request tosend
      - Builds `msg_C` + `nonce_C` + `timestamp_C` including `pk_C`
      - Generates schnorr signature `sig_C = (g^k, k + H(g^k || pk_C || M))` and includes in message headers
    - given `pk_CA` and incoming request:
      - verifies `Cert_C`
        - rebuilds `msg_C`
        - extract `pk_C` from `Cert_C`
        - extract `sig_C` from headers
        - verfies `sig_C` using `pk_C` & M: `e=H(g^k || pk_C || M`, `g^s == R & pk_C ^ e`
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
    

