import bsv from "bsv";
import crypto from "crypto";

export class Hash {
  constructor() {
    this.bsv = bsv;
  }

  /**
   * Computes SHA256 hash of input data
   * @param {string|Buffer|Array} data - Input data to hash
   * @returns {string} Hex string of hash
   */
  hash256(data) {
    if (Array.isArray(data)) {
      data = Buffer.from(data);
    } else if (typeof data === "string") {
      data = Buffer.from(data, "utf8");
    }
    const hashbuf = bsv.crypto.Hash.sha256(data);
    return hashbuf.toString("hex");
  }

  /**
   * Computes SHA512 hash of input data
   * @param {string|Buffer|Array} data - Input data to hash
   * @returns {string} Hex string of hash
   */
  hash512(data) {
    if (Array.isArray(data)) {
      data = Buffer.from(data);
    } else if (typeof data === "string") {
      data = Buffer.from(data, "utf8");
    }
    const hashbuf = bsv.crypto.Hash.sha512(data);
    return hashbuf.toString("hex");
  }

  /**
   * Double SHA256 hash (commonly used in Bitcoin)
   * @param {string|Buffer|Array} data - Input data to hash
   * @returns {string} Hex string of double hash
   */
  doubleHash256(data) {
    if (Array.isArray(data)) {
      data = Buffer.from(data);
    } else if (typeof data === "string") {
      data = Buffer.from(data, "utf8");
    }
    const hash1 = bsv.crypto.Hash.sha256(data);
    const hash2 = bsv.crypto.Hash.sha256(hash1);
    return hash2.toString("hex");
  }

  /**
   * Computes RIPEMD160(SHA256()) hash (commonly used for Bitcoin addresses)
   * @param {string|Buffer|Array} data - Input data to hash
   * @returns {string} Hex string of hash
   */
  hash160(data) {
    if (Array.isArray(data)) {
      data = Buffer.from(data);
    } else if (typeof data === "string") {
      data = Buffer.from(data, "utf8");
    }
    const hash = bsv.crypto.Hash.sha256ripemd160(data);
    return hash.toString("hex");
  }

  /**
   * Verifies if a given hash matches the data
   * @param {string} data - Original data
   * @param {string} hash - Hash to verify against
   * @param {string} algorithm - Hash algorithm to use (256, 512, double256, 160)
   * @returns {boolean} True if hash matches
   */
  verifyHash(data, hash, algorithm = "256") {
    let computedHash;
    switch (algorithm) {
      case "256":
        computedHash = this.hash256(data);
        break;
      case "512":
        computedHash = this.hash512(data);
        break;
      case "double256":
        computedHash = this.doubleHash256(data);
        break;
      case "160":
        computedHash = this.hash160(data);
        break;
      default:
        throw new Error("Unsupported hash algorithm");
    }
    return computedHash === hash;
  }
}

// Create singleton instance
export default new Hash();

// Test example
if (import.meta.url === `file://${process.cwd()}/Hashes.js`) {
  const hash = new Hash();
  const testData = "Hello, SmartLedger!";
  
  console.log("Test Data:", testData);
  console.log("SHA256:", hash.hash256(testData));
  console.log("SHA512:", hash.hash512(testData));
  console.log("Double SHA256:", hash.doubleHash256(testData));
  console.log("HASH160 (RIPEMD160(SHA256)):", hash.hash160(testData));
  
  // Test verification
  const testHash = hash.hash256(testData);
  console.log("\nHash Verification Test:");
  console.log("Original Hash:", testHash);
  console.log("Verification Result:", hash.verifyHash(testData, testHash, "256"));
}
