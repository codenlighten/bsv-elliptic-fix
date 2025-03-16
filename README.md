# BSV Key Management System

A comprehensive Bitcoin SV (BSV) key management system with support for key generation, signing, encryption, hashing, and Shamir Secret Sharing.

## Features

### Key Generation
- 24-word mnemonic generation using secure entropy
- BIP44 hierarchical deterministic key derivation
- Multiple key types with standard paths:
  - Identity (m/44'/236'/0'/0/0)
  - Financial (m/44'/0'/0'/0/0)
  - Contractual (m/44'/236'/1'/0/0)
  - Property (m/44'/236'/2'/0/0)
  - Document (m/44'/236'/3'/0/0)
  - Privacy (m/44'/236'/4'/0/0)
- Deterministic key generation (same mnemonic produces same keys)

### Signing
- ECDSA signatures
  - Returns DER-encoded signatures
  - Verification using public key
- EdDSA signatures
  - Uses Ed25519 curve
  - Returns 128-character hex signatures
  - Verification using WIF key
- Comprehensive error handling

### Hashing
- SHA256
- SHA512
- Double SHA256 (Bitcoin's hash)
- HASH160 (RIPEMD160(SHA256))
- Hash verification support

### Encryption
- AES encryption/decryption
- Password-based key derivation
- Support for both string and JSON data
- Secure salting

### Shamir Secret Sharing
- Split secrets into configurable shares
  - Minimum 2 shares required
  - Configurable threshold (>= 2 and <= total shares)
  - Returns hex-encoded shares
- Combine shares to recover secrets
  - Validates hex format of shares
  - UTF-8 validation for reconstructed secrets
  - Error handling for invalid combinations

## Web Interface
The system includes a modern web interface built with Tailwind CSS that provides access to all functionality:
- Key generation with mnemonic display
- Signing interface for both ECDSA and EdDSA
- Hash computation with multiple algorithms
- Encryption/decryption tools
- Shamir Secret Sharing with dynamic share management

## Security Features
- Input validation across all operations
- Secure random number generation
- Error handling for all cryptographic operations
- Protection against invalid share combinations
- Hex and UTF-8 validation for shares and secrets

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
```

2. Install dependencies:
```bash
npm install
```

3. Start the server:
```bash
node index.js
```

4. Access the web interface at http://localhost:3000

## API Endpoints

### Key Management
- POST /keys/generate - Generate new keys with mnemonic
- POST /keys/from-mnemonic - Recover keys from mnemonic

### Signing
- POST /sign/ecdsa - Sign data using ECDSA
- POST /sign/eddsa - Sign data using EdDSA

### Hashing
- POST /hash - Compute hash with specified algorithm

### Encryption
- POST /encrypt - Encrypt data
- POST /decrypt - Decrypt data

### Shamir Secret Sharing
- POST /shamir/split - Split a secret into shares
- POST /shamir/combine - Combine shares to recover secret

## Testing
The system includes comprehensive test suites for all components:
- Key generation and derivation tests
- Signature creation and verification tests
- Hash function tests
- Encryption/decryption tests
- Shamir Secret Sharing tests with BSV-specific scenarios

## Security Considerations
1. Always use secure entropy for key generation
2. Store mnemonics and keys securely
3. Use appropriate thresholds for Shamir Secret Sharing
4. Validate all inputs and outputs
5. Handle errors appropriately

## Dependencies
- bsv: Bitcoin SV library
- crypto-js: For AES encryption
- shamirs-secret-sharing: For Shamir Secret Sharing
- express: Web server
- cors: Cross-origin resource sharing
