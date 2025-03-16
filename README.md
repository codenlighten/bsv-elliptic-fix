# bsv-elliptic-fix

A secure Bitcoin SV (BSV) cryptographic library implementation with hardened key generation and signing capabilities.

## Features

### Key Generation
- 24-word mnemonic generation using secure entropy
- BIP44 compliant HD key derivation
- Multiple key types:
  - Identity (m/44'/236'/0'/0/0)
  - Financial (m/44'/0'/0'/0/0)
  - Contractual (m/44'/236'/1'/0/0)
  - Property (m/44'/236'/2'/0/0)
  - Document (m/44'/236'/3'/0/0)
  - Privacy (m/44'/236'/4'/0/0)

### Signing
- ECDSA signatures with DER encoding
- EdDSA signatures (Ed25519)
- Secure signature verification

### API Endpoints
- POST /keys/generate - Generate new key pairs
- POST /keys/from-mnemonic - Generate keys from mnemonic
- POST /sign/ecdsa - Create ECDSA signature
- POST /sign/eddsa - Create EdDSA signature
- POST /verify/ecdsa - Verify ECDSA signature
- POST /verify/eddsa - Verify EdDSA signature
- POST /hash - Create hash (sha256, sha512, double256, hash160)
- POST /hash/verify - Verify hash
- POST /encrypt - Encrypt data
- POST /decrypt - Decrypt data
- GET /health - Health check

## Installation

```bash
npm install
```

## Usage

Start the server:
```bash
node index.js
```

The server will run on port 3000 by default.

## Security

- Uses cryptographically secure random number generation
- Implements BIP44 standard for HD wallet derivation
- Proper error handling and input validation
- Secure key storage practices
