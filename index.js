import express from "express";
import cors from "cors";
import { BSVKeys } from "./Keys.js";
import { BSVSignature } from "./Signature.js";
import Hash from "./Hashes.js";
import Shamir from "./Shamir.js";
import * as Encryption from "./Encryption.js";
import swaggerUi from "swagger-ui-express";
import specs from "./swagger.js";
import { v4 as uuidv4 } from "uuid";

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs));

/**
 * @swagger
 * components:
 *   schemas:
 *     KeyResponse:
 *       type: object
 *       properties:
 *         mnemonic:
 *           type: string
 *           description: 24-word mnemonic phrase
 *         keys:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               type:
 *                 type: string
 *                 enum: [identity, financial, contractual, property, document, privacy]
 *               path:
 *                 type: string
 *                 description: BIP44 derivation path
 *               wif:
 *                 type: string
 *                 description: Wallet Import Format key
 *               publicKey:
 *                 type: string
 *                 description: Public key in hex format
 *               address:
 *                 type: string
 *                 description: BSV address
 */

/**
 * @swagger
 * /api/keys/generate:
 *   post:
 *     summary: Generate new BSV keys with mnemonic
 *     description: Generates a new 24-word mnemonic and derives multiple key types using BIP44 paths
 *     tags: [Keys]
 *     responses:
 *       200:
 *         description: Successfully generated keys
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/KeyResponse'
 */
app.post("/api/keys/generate", (req, res) => {
  try {
    const keys = BSVKeys.generateAllKeys();
    res.json({ success: true, data: keys });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * @swagger
 * /api/keys/from-mnemonic:
 *   post:
 *     summary: Generate keys from existing mnemonic
 *     description: Derives multiple key types from a provided mnemonic using BIP44 paths
 *     tags: [Keys]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [mnemonic]
 *             properties:
 *               mnemonic:
 *                 type: string
 *                 description: 24-word mnemonic phrase
 *     responses:
 *       200:
 *         description: Successfully generated keys
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/KeyResponse'
 */
app.post("/api/keys/from-mnemonic", (req, res) => {
  try {
    const { mnemonic } = req.body;
    if (!mnemonic) throw new Error("Mnemonic is required");

    // Create base instance to get paths
    const baseInstance = new BSVKeys();
    const result = {
      mnemonic,
      keys: [],
      uuid: baseInstance.uuid,
    };

    // Generate keys for each purpose
    for (const [type, path] of Object.entries(baseInstance.paths)) {
      const derivedKey = BSVKeys.fromMnemonic(mnemonic, type);
      result.keys.push({
        type,
        path,
        wif: derivedKey.toWIF(),
        publicKey: derivedKey.publicKey.toString(),
        address: derivedKey.toAddress(),
      });
    }

    res.json({ success: true, data: result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

/**
 * @swagger
 * /api/sign/ecdsa:
 *   post:
 *     summary: Create ECDSA signature
 *     description: Signs data using ECDSA and returns a DER-encoded signature
 *     tags: [Signatures]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [data, wif]
 *             properties:
 *               data:
 *                 type: string
 *                 description: Data to sign
 *               wif:
 *                 type: string
 *                 description: WIF private key
 *     responses:
 *       200:
 *         description: Successfully created signature
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 signature:
 *                   type: string
 *                   description: DER-encoded signature
 */
app.post("/api/sign/ecdsa", (req, res) => {
  try {
    const { data, wif, purpose } = req.body;
    if (!data || !wif) throw new Error("Data and WIF are required");

    const signer = BSVSignature.fromWIF(wif);
    const signature = signer.sign(data);
    res.json({
      success: true,
      data: {
        signature: signature.toString(),
        publicKey: signer.getPublicKey().toString(),
      },
    });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

/**
 * @swagger
 * /api/sign/eddsa:
 *   post:
 *     summary: Create EdDSA signature
 *     description: Signs data using EdDSA (Ed25519) and returns a 128-character hex signature
 *     tags: [Signatures]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [data, wif]
 *             properties:
 *               data:
 *                 type: string
 *                 description: Data to sign
 *               wif:
 *                 type: string
 *                 description: WIF private key
 *     responses:
 *       200:
 *         description: Successfully created signature
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 signature:
 *                   type: string
 *                   description: 128-character hex signature
 */
app.post("/api/sign/eddsa", (req, res) => {
  try {
    const { data, wif } = req.body;
    if (!data || !wif) throw new Error("Data and WIF are required");

    const signer = BSVSignature.fromWIF(wif);
    const signature = signer.signEdDSA(data);
    res.json({
      success: true,
      data: {
        signature: signature,
        publicKey: signer.getEdDSAPublicKey(),
      },
    });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

/**
 * @swagger
 * /api/verify/ecdsa:
 *   post:
 *     summary: Verify ECDSA signature
 *     description: Verifies a signature using ECDSA
 *     tags: [Signatures]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [data, signature, publicKey]
 *             properties:
 *               data:
 *                 type: string
 *                 description: Data to verify
 *               signature:
 *                 type: string
 *                 description: DER-encoded signature
 *               publicKey:
 *                 type: string
 *                 description: Public key in hex format
 *     responses:
 *       200:
 *         description: Successfully verified signature
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 isValid:
 *                   type: boolean
 *                   description: Whether the signature is valid
 */
app.post("/api/verify/ecdsa", (req, res) => {
  try {
    const { data, signature, publicKey } = req.body;
    if (!data || !signature || !publicKey) {
      throw new Error("Data, signature, and public key are required");
    }

    const verifier = BSVSignature.fromPublicKey(publicKey);
    const isValid = verifier.verify(data, signature);
    res.json({ success: true, data: { isValid } });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

/**
 * @swagger
 * /api/verify/eddsa:
 *   post:
 *     summary: Verify EdDSA signature
 *     description: Verifies a signature using EdDSA (Ed25519)
 *     tags: [Signatures]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [data, signature, wif]
 *             properties:
 *               data:
 *                 type: string
 *                 description: Data to verify
 *               signature:
 *                 type: string
 *                 description: 128-character hex signature
 *               wif:
 *                 type: string
 *                 description: WIF private key
 *     responses:
 *       200:
 *         description: Successfully verified signature
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 isValid:
 *                   type: boolean
 *                   description: Whether the signature is valid
 */
app.post("/api/verify/eddsa", (req, res) => {
  try {
    const { data, signature, wif } = req.body;
    if (!data || !signature || !wif) {
      throw new Error("Data, signature, and WIF are required");
    }

    const verifier = BSVSignature.fromWIF(wif);
    const isValid = verifier.verifyEdDSA(data, signature);
    res.json({ success: true, data: { isValid } });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

/**
 * @swagger
 * /api/hash:
 *   post:
 *     summary: Create hash
 *     description: Creates a hash of the input data using the specified algorithm
 *     tags: [Hashing]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [data, algorithm]
 *             properties:
 *               data:
 *                 type: string
 *                 description: Data to hash
 *               algorithm:
 *                 type: string
 *                 enum: [256, 512, double256, 160]
 *                 description: Hash algorithm to use
 *     responses:
 *       200:
 *         description: Successfully created hash
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 hash:
 *                   type: string
 *                   description: Resulting hash in hex format
 */
app.post("/api/hash", (req, res) => {
  try {
    const { data, algorithm } = req.body;
    if (!data) throw new Error("Data is required");

    let result;
    switch (algorithm) {
      case "sha256":
        result = Hash.hash256(data);
        break;
      case "sha512":
        result = Hash.hash512(data);
        break;
      case "double256":
        result = Hash.doubleHash256(data);
        break;
      case "hash160":
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

/**
 * @swagger
 * /api/hash/verify:
 *   post:
 *     summary: Verify hash
 *     description: Verifies a hash using the specified algorithm
 *     tags: [Hashing]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [data, hash, algorithm]
 *             properties:
 *               data:
 *                 type: string
 *                 description: Data to verify
 *               hash:
 *                 type: string
 *                 description: Hash to verify
 *               algorithm:
 *                 type: string
 *                 enum: [256, 512, double256, 160]
 *                 description: Hash algorithm to use
 *     responses:
 *       200:
 *         description: Successfully verified hash
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 isValid:
 *                   type: boolean
 *                   description: Whether the hash is valid
 */
app.post("/api/hash/verify", (req, res) => {
  try {
    const { data, hash, algorithm } = req.body;
    if (!data || !hash) throw new Error("Data and hash are required");

    const isValid = Hash.verifyHash(data, hash, algorithm || "256");
    res.json({ success: true, data: { isValid } });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

/**
 * @swagger
 * /api/encrypt:
 *   post:
 *     summary: Encrypt data
 *     description: Encrypts data using AES with password-based key derivation
 *     tags: [Encryption]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [data, key]
 *             properties:
 *               data:
 *                 type: string
 *                 description: Data to encrypt
 *               key:
 *                 type: string
 *                 description: Encryption key/password
 *     responses:
 *       200:
 *         description: Successfully encrypted data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 encrypted:
 *                   type: string
 *                   description: Encrypted data in base64 format
 */
app.post("/api/encrypt", (req, res) => {
  try {
    const { data, key, isObject } = req.body;
    if (!data || !key) throw new Error("Data and key are required");

    const encrypted = isObject
      ? Encryption.encryptObject(data, key)
      : Encryption.encrypt(data, key);

    res.json({ success: true, data: { encrypted } });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

/**
 * @swagger
 * /api/decrypt:
 *   post:
 *     summary: Decrypt data
 *     description: Decrypts AES-encrypted data using the provided key
 *     tags: [Encryption]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [data, key]
 *             properties:
 *               data:
 *                 type: string
 *                 description: Encrypted data in base64 format
 *               key:
 *                 type: string
 *                 description: Decryption key/password
 *     responses:
 *       200:
 *         description: Successfully decrypted data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 decrypted:
 *                   type: string
 *                   description: Decrypted data
 */
app.post("/api/decrypt", (req, res) => {
  try {
    const { data, key, isObject } = req.body;
    if (!data || !key) throw new Error("Data and key are required");

    const decrypted = isObject
      ? Encryption.decryptObject(data, key)
      : Encryption.decrypt(data, key);

    res.json({ success: true, data: { decrypted } });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

/**
 * @swagger
 * /api/shamir/split:
 *   post:
 *     summary: Split a secret using Shamir's Secret Sharing
 *     description: Splits a secret into multiple shares with a configurable threshold
 *     tags: [Shamir]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [secret, shares, threshold]
 *             properties:
 *               secret:
 *                 type: string
 *                 description: Secret to split
 *               shares:
 *                 type: integer
 *                 minimum: 2
 *                 description: Number of shares to create
 *               threshold:
 *                 type: integer
 *                 minimum: 2
 *                 description: Number of shares required to reconstruct
 *     responses:
 *       200:
 *         description: Successfully split secret
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 shares:
 *                   type: array
 *                   items:
 *                     type: string
 *                   description: Array of hex-encoded shares
 */
app.post("/api/shamir/split", (req, res) => {
  try {
    const { secret, shares, threshold } = req.body;
    if (!secret) throw new Error("Secret is required");
    if (!shares || !Number.isInteger(shares) || shares < 2) {
      throw new Error("Shares must be an integer >= 2");
    }
    if (
      !threshold ||
      !Number.isInteger(threshold) ||
      threshold < 2 ||
      threshold > shares
    ) {
      throw new Error("Threshold must be an integer >= 2 and <= shares");
    }

    const shamir = new Shamir();
    const splitShares = shamir.split(secret, { shares, threshold });
    res.json({
      success: true,
      data: {
        shares: splitShares,
        totalShares: shares,
        requiredShares: threshold,
      },
    });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

/**
 * @swagger
 * /api/shamir/combine:
 *   post:
 *     summary: Combine Shamir secret shares
 *     description: Combines the provided shares to reconstruct the original secret
 *     tags: [Shamir]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [shares]
 *             properties:
 *               shares:
 *                 type: array
 *                 items:
 *                   type: string
 *                 minItems: 2
 *                 description: Array of hex-encoded shares
 *     responses:
 *       200:
 *         description: Successfully reconstructed secret
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 secret:
 *                   type: string
 *                   description: Reconstructed secret
 */
app.post("/api/shamir/combine", (req, res) => {
  try {
    const { shares } = req.body;
    if (!shares || !Array.isArray(shares)) {
      throw new Error("Shares must be provided as an array");
    }
    if (shares.length < 2) {
      throw new Error(
        "At least 2 shares are required to reconstruct the secret"
      );
    }
    if (
      !shares.every(
        (share) => typeof share === "string" && /^[0-9a-fA-F]+$/.test(share)
      )
    ) {
      throw new Error("All shares must be valid hex strings");
    }

    const shamir = new Shamir();
    const secret = shamir.combine(shares);

    // Verify the secret is valid UTF-8
    try {
      const secretStr = secret.toString("utf8");
      res.json({ success: true, data: { secret: secretStr } });
    } catch (e) {
      throw new Error(
        "Failed to reconstruct secret: invalid share combination"
      );
    }
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// UUID endpoint
/**
 * @swagger
 * /api/uuid:
 *   get:
 *     summary: Generate a UUID
 *     description: Generates a random UUID
 *     tags: [Utility]
 *     responses:
 *       200:
 *         description: Successfully generated UUID
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 uuid:
 *                   type: string
 *                   description: Generated UUID
 */
app.get("/api/uuid", (req, res) => {
  res.json({ uuid: uuidv4() });
});

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`
Available endpoints:
- POST /api/keys/generate              Generate new key pairs
- POST /api/keys/from-mnemonic        Generate keys from mnemonic
- POST /api/sign/ecdsa                Create ECDSA signature
- POST /api/sign/eddsa                Create EdDSA signature
- POST /api/verify/ecdsa              Verify ECDSA signature
- POST /api/verify/eddsa              Verify EdDSA signature
- POST /api/hash                      Create hash (sha256, sha512, double256, hash160)
- POST /api/hash/verify              Verify hash
- POST /api/encrypt                   Encrypt data
- POST /api/decrypt                   Decrypt data
- POST /api/shamir/split              Split secret using Shamir's Secret Sharing
- POST /api/shamir/combine            Combine shares to reconstruct secret
- GET  /api/uuid                      Generate a UUID
- GET  /api/health                    Health check
    `);
});
