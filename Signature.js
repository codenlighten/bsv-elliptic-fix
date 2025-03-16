import bsv from "bsv";
import { BSVKeys } from "./Keys.js";
import elliptic from "@smartledger/elliptic-fix";

// Initialize EdDSA with our hardened version
const ed25519 = new elliptic.eddsa('ed25519');

export class BSVSignature {
  privateKey;
  publicKey;
  purpose;
  eddsaKeyPair;

  constructor() {
    this.bsv = bsv;
  }

  static fromWIF(wif) {
    const privateKey = bsv.PrivateKey.fromWIF(wif);
    const instance = new BSVSignature();
    instance.privateKey = privateKey;
    instance.publicKey = privateKey.publicKey;
    // Generate EdDSA keypair from the same private key bytes
    instance.eddsaKeyPair = ed25519.keyFromSecret(privateKey.bn.toBuffer());
    return instance;
  }

  static fromPrivateKey(privateKey, purpose = null) {
    const instance = new BSVSignature();
    instance.privateKey = privateKey;
    instance.publicKey = privateKey.publicKey;
    instance.purpose = purpose;
    // Generate EdDSA keypair from the same private key bytes
    instance.eddsaKeyPair = ed25519.keyFromSecret(privateKey.bn.toBuffer());
    return instance;
  }

  static fromMnemonic(mnemonic, purpose = "document") {
    const keys = BSVKeys.fromMnemonic(mnemonic, purpose);
    return this.fromPrivateKey(keys.privateKey, purpose);
  }

  static fromPublicKey(publicKeyHex, purpose = null) {
    const instance = new BSVSignature();
    instance.publicKey = bsv.PublicKey.fromString(publicKeyHex);
    instance.purpose = purpose;
    return instance;
  }

  // Original ECDSA signing
  sign(data) {
    if (!this.privateKey) {
      throw new Error("Private key is required for signing");
    }
    const hashbuf = bsv.crypto.Hash.sha256(Buffer.from(data, "utf8"));
    const sig = bsv.crypto.ECDSA.sign(hashbuf, this.privateKey);
    return sig;
  }

  // New EdDSA signing
  signEdDSA(data) {
    if (!this.eddsaKeyPair) {
      throw new Error("EdDSA key pair is required for signing");
    }
    const message = Buffer.from(data, "utf8");
    return this.eddsaKeyPair.sign(message).toHex();
  }

  // Original ECDSA verification
  verify(data, signatureHex) {
    try {
      const hashbuf = bsv.crypto.Hash.sha256(Buffer.from(data, "utf8"));
      const signature = bsv.crypto.Signature.fromString(signatureHex);
      return bsv.crypto.ECDSA.verify(hashbuf, signature, this.publicKey);
    } catch (error) {
      console.error("Verification error:", error);
      return false;
    }
  }

  // New EdDSA verification
  verifyEdDSA(data, signatureHex) {
    try {
      if (!this.eddsaKeyPair) {
        throw new Error("EdDSA key pair is required for verification");
      }
      const message = Buffer.from(data, "utf8");
      return this.eddsaKeyPair.verify(message, signatureHex);
    } catch (error) {
      console.error("EdDSA Verification error:", error);
      return false;
    }
  }

  verifyFromPublicKey(data, signatureHex, publicKeyHex) {
    try {
      const publicKey = bsv.PublicKey.fromString(publicKeyHex);
      const hashbuf = bsv.crypto.Hash.sha256(Buffer.from(data, "utf8"));
      const signature = bsv.crypto.Signature.fromString(signatureHex);
      return bsv.crypto.ECDSA.verify(hashbuf, signature, publicKey);
    } catch (error) {
      console.error("Verification error:", error);
      return false;
    }
  }

  getPublicKey() {
    return this.publicKey;
  }

  getEdDSAPublicKey() {
    return this.eddsaKeyPair ? this.eddsaKeyPair.getPublic('hex') : null;
  }

  getPurpose() {
    return this.purpose;
  }
}

// Test example
if (import.meta.url === `file://${process.cwd()}/Signature.js`) {
  try {
    // Generate a new mnemonic
    const mnemonic = BSVKeys.generateMnemonic();
    console.log("Mnemonic:", mnemonic.toString());

    // Test both ECDSA and EdDSA signatures
    const testData = "Hello, Web3Keys!";
    console.log("\nTesting signatures with data:", testData);

    const signer = BSVSignature.fromMnemonic(mnemonic, "test");

    // Test ECDSA
    console.log("\nECDSA Test:");
    const ecdsaSig = signer.sign(testData);
    console.log("ECDSA Signature:", ecdsaSig.toString());
    console.log("ECDSA Public Key:", signer.getPublicKey().toString());
    console.log("ECDSA Verification:", signer.verify(testData, ecdsaSig.toString()));

    // Test EdDSA
    console.log("\nEdDSA Test:");
    const eddsaSig = signer.signEdDSA(testData);
    console.log("EdDSA Signature:", eddsaSig);
    console.log("EdDSA Public Key:", signer.getEdDSAPublicKey());
    console.log("EdDSA Verification:", signer.verifyEdDSA(testData, eddsaSig));

    // Test EdDSA signature malleability protection
    console.log("\nTesting EdDSA signature malleability protection:");
    const ed = new elliptic.eddsa('ed25519');
    const validSig = Buffer.from(eddsaSig, 'hex');
    const R = validSig.slice(0, 32);
    const malleableS = ed.curve.n.addn(1); // S = n + 1
    const malleableSBytes = malleableS.toArrayLike(Buffer, 'le', 32);
    const malleableSig = Buffer.concat([R, malleableSBytes]).toString('hex');
    
    console.log("Malleable Signature Verification:", signer.verifyEdDSA(testData, malleableSig));
    console.log("(Should be false if protection is working)");

  } catch (error) {
    console.error("Error:", error.message);
  }
}
