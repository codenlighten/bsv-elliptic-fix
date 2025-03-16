import express from 'express';
import cors from 'cors';
import { BSVKeys } from './Keys.js';
import { BSVSignature } from './Signature.js';
import Hash from './Hashes.js';
import * as Encryption from './Encryption.js';

const app = express();
app.use(cors());
app.use(express.json());

// Key Management Endpoints
app.post('/keys/generate', (req, res) => {
    try {
        const keys = BSVKeys.generateAllKeys();
        res.json({ success: true, data: keys });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/keys/from-mnemonic', (req, res) => {
    try {
        const { mnemonic } = req.body;
        if (!mnemonic) throw new Error('Mnemonic is required');
        
        // Create base instance to get paths
        const baseInstance = new BSVKeys();
        const result = {
            mnemonic,
            keys: [],
            uuid: baseInstance.uuid
        };

        // Generate keys for each purpose
        for (const [type, path] of Object.entries(baseInstance.paths)) {
            const derivedKey = BSVKeys.fromMnemonic(mnemonic, type);
            result.keys.push({
                type,
                path,
                wif: derivedKey.toWIF(),
                publicKey: derivedKey.publicKey.toString(),
                address: derivedKey.toAddress()
            });
        }

        res.json({ success: true, data: result });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

// Signature Endpoints
app.post('/sign/ecdsa', (req, res) => {
    try {
        const { data, wif, purpose } = req.body;
        if (!data || !wif) throw new Error('Data and WIF are required');

        const signer = BSVSignature.fromWIF(wif);
        const signature = signer.sign(data);
        res.json({
            success: true,
            data: {
                signature: signature.toString(),
                publicKey: signer.getPublicKey().toString()
            }
        });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

app.post('/sign/eddsa', (req, res) => {
    try {
        const { data, wif } = req.body;
        if (!data || !wif) throw new Error('Data and WIF are required');

        const signer = BSVSignature.fromWIF(wif);
        const signature = signer.signEdDSA(data);
        res.json({
            success: true,
            data: {
                signature: signature,
                publicKey: signer.getEdDSAPublicKey()
            }
        });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

app.post('/verify/ecdsa', (req, res) => {
    try {
        const { data, signature, publicKey } = req.body;
        if (!data || !signature || !publicKey) {
            throw new Error('Data, signature, and public key are required');
        }

        const verifier = BSVSignature.fromPublicKey(publicKey);
        const isValid = verifier.verify(data, signature);
        res.json({ success: true, data: { isValid } });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

app.post('/verify/eddsa', (req, res) => {
    try {
        const { data, signature, wif } = req.body;
        if (!data || !signature || !wif) {
            throw new Error('Data, signature, and WIF are required');
        }

        const verifier = BSVSignature.fromWIF(wif);
        const isValid = verifier.verifyEdDSA(data, signature);
        res.json({ success: true, data: { isValid } });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

// Hash Endpoints
app.post('/hash', (req, res) => {
    try {
        const { data, algorithm } = req.body;
        if (!data) throw new Error('Data is required');

        let result;
        switch (algorithm) {
            case 'sha256':
                result = Hash.hash256(data);
                break;
            case 'sha512':
                result = Hash.hash512(data);
                break;
            case 'double256':
                result = Hash.doubleHash256(data);
                break;
            case 'hash160':
                result = Hash.hash160(data);
                break;
            default:
                result = Hash.hash256(data);
        }

        res.json({ success: true, data: { hash: result } });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

app.post('/hash/verify', (req, res) => {
    try {
        const { data, hash, algorithm } = req.body;
        if (!data || !hash) throw new Error('Data and hash are required');

        const isValid = Hash.verifyHash(data, hash, algorithm || '256');
        res.json({ success: true, data: { isValid } });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

// Encryption Endpoints
app.post('/encrypt', (req, res) => {
    try {
        const { data, key, isObject } = req.body;
        if (!data || !key) throw new Error('Data and key are required');

        const encrypted = isObject ? 
            Encryption.encryptObject(data, key) : 
            Encryption.encrypt(data, key);

        res.json({ success: true, data: { encrypted } });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

app.post('/decrypt', (req, res) => {
    try {
        const { data, key, isObject } = req.body;
        if (!data || !key) throw new Error('Data and key are required');

        const decrypted = isObject ?
            Encryption.decryptObject(data, key) :
            Encryption.decrypt(data, key);

        res.json({ success: true, data: { decrypted } });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`
Available endpoints:
- POST /keys/generate              Generate new key pairs
- POST /keys/from-mnemonic        Generate keys from mnemonic
- POST /sign/ecdsa                Create ECDSA signature
- POST /sign/eddsa                Create EdDSA signature
- POST /verify/ecdsa              Verify ECDSA signature
- POST /verify/eddsa              Verify EdDSA signature
- POST /hash                      Create hash (sha256, sha512, double256, hash160)
- POST /hash/verify              Verify hash
- POST /encrypt                   Encrypt data
- POST /decrypt                   Decrypt data
- GET  /health                    Health check
    `);
});