import bsv from "bsv";
import Mnemonic from "bsv/mnemonic/index.js";
import { v4 as uuidv4 } from "uuid";
import crypto from 'crypto';

export class BSVKeys {
  constructor() {
    this.bsv = bsv;
    this.paths = {
      identity: "m/44'/236'/0'/0/0",
      financial: "m/44'/0'/0'/0/0",
      contractual: "m/44'/236'/1'/0/0",
      property: "m/44'/236'/2'/0/0",
      document: "m/44'/236'/3'/0/0",
      privacy: "m/44'/236'/4'/0/0",
    };
    this.uuid = uuidv4();
  }

  static generateMnemonic() {
    try {
      // Generate 256 bits (32 bytes) of entropy for 24 words
      const entropy = crypto.randomBytes(32);
      
      // Create mnemonic with 256 bits of entropy
      const mnemonic = new Mnemonic(entropy);
      
      // Verify we have 24 words
      const words = mnemonic.toString().split(" ");
      if (words.length !== 24) {
        console.error("Generated mnemonic has", words.length, "words instead of 24");
        return BSVKeys.generateMnemonic();
      }
      return mnemonic;
    } catch (error) {
      console.error("Error generating mnemonic:", error);
      throw new Error("Failed to generate secure mnemonic");
    }
  }

  static fromMnemonic(mnemonic, purpose = "financial") {
    try {
      if (typeof mnemonic === "string") {
        mnemonic = Mnemonic.fromString(mnemonic);
      }
      const instance = new BSVKeys();
      const path = instance.paths[purpose] || instance.paths.financial;
      const hdPrivateKey = mnemonic.toHDPrivateKey();
      const derivedKey = hdPrivateKey.deriveChild(path);
      instance.privateKey = derivedKey.privateKey;
      instance.publicKey = instance.privateKey.publicKey;
      instance.hdPrivateKey = hdPrivateKey;
      instance.path = path;
      return instance;
    } catch (error) {
      console.error("Error creating keys from mnemonic:", error);
      throw new Error("Invalid mnemonic phrase");
    }
  }

  static fromWIF(wif) {
    try {
      const privateKey = bsv.PrivateKey.fromWIF(wif);
      const instance = new BSVKeys();
      instance.privateKey = privateKey;
      instance.publicKey = privateKey.publicKey;
      return instance;
    } catch (error) {
      console.error("Error creating keys from WIF:", error);
      throw new Error("Invalid WIF format");
    }
  }

  static fromPrivateKey(privateKey) {
    try {
      const instance = new BSVKeys();
      instance.privateKey = privateKey;
      instance.publicKey = privateKey.publicKey;
      return instance;
    } catch (error) {
      console.error("Error creating keys from private key:", error);
      throw new Error("Invalid private key");
    }
  }

  toWIF() {
    if (!this.privateKey) {
      throw new Error("Private key is required for WIF format");
    }
    return this.privateKey.toWIF();
  }

  toPublicKeyString() {
    return this.publicKey.toString();
  }

  toAddress() {
    return this.publicKey.toAddress().toString();
  }

  deriveChild(path) {
    if (!this.hdPrivateKey) {
      throw new Error(
        "HD Private key is required for derivation. Use fromMnemonic to create a derivable key."
      );
    }
    const derivedKey = this.hdPrivateKey.deriveChild(path);
    const instance = new BSVKeys();
    instance.privateKey = derivedKey.privateKey;
    instance.publicKey = instance.privateKey.publicKey;
    instance.hdPrivateKey = derivedKey;
    instance.path = path;
    return instance;
  }

  deriveForPurpose(purpose) {
    if (!this.hdPrivateKey) {
      throw new Error(
        "HD Private Key not available. Keys must be created from mnemonic to derive for different purposes."
      );
    }
    const path = this.paths[purpose] || this.paths.financial;
    const derivedKey = this.hdPrivateKey.deriveChild(path);
    const instance = new BSVKeys();
    instance.privateKey = derivedKey.privateKey;
    instance.publicKey = instance.privateKey.publicKey;
    instance.hdPrivateKey = this.hdPrivateKey;
    instance.path = path;
    return instance;
  }

  static generateAllKeys() {
    try {
      const mnemonic = this.generateMnemonic();
      const instance = new BSVKeys();
      const keys = {
        mnemonic: mnemonic.toString(),
        keys: [],
        uuid: instance.uuid,
      };

      for (const [type, path] of Object.entries(instance.paths)) {
        const derivedKey = this.fromMnemonic(mnemonic, type);
        keys.keys.push({
          type,
          path,
          wif: derivedKey.toWIF(),
          publicKey: derivedKey.publicKey.toString(),
          address: derivedKey.toAddress(),
        });
      }

      return keys;
    } catch (error) {
      console.error("Error generating all keys:", error);
      throw new Error("Failed to generate key set");
    }
  }
}
