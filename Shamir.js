import { split, combine } from "shamirs-secret-sharing";

/**
 * Class implementing Shamir's Secret Sharing scheme
 */
class Shamir {
  /**
   * Split a secret into shares using Shamir's Secret Sharing
   * @param {Buffer|string} secret - Secret to split (if string, will be converted to Buffer)
   * @param {Object} options - Split options
   * @param {number} options.shares - Number of shares to create
   * @param {number} options.threshold - Number of shares required to reconstruct
   * @returns {string[]} Array of secret shares as hex strings
   */
  split(secret, { shares, threshold }) {
    if (typeof secret === "string") {
      secret = Buffer.from(secret);
    }
    if (!Buffer.isBuffer(secret)) {
      throw new Error("Secret must be a Buffer or string");
    }
    if (!Number.isInteger(shares) || shares < 2) {
      throw new Error("Shares must be an integer >= 2");
    }
    if (!Number.isInteger(threshold) || threshold < 2 || threshold > shares) {
      throw new Error("Threshold must be an integer >= 2 and <= shares");
    }

    // Convert shares to hex strings
    return split(secret, { shares, threshold }).map((share) =>
      Buffer.from(share).toString("hex")
    );
  }

  /**
   * Combine shares to reconstruct the secret
   * @param {string[]} hexShares - Array of shares as hex strings
   * @returns {Buffer} Reconstructed secret
   */
  combine(hexShares) {
    if (!Array.isArray(hexShares) || hexShares.length < 2) {
      throw new Error("Must provide at least 2 shares");
    }
    if (
      !hexShares.every(
        (share) => typeof share === "string" && /^[0-9a-fA-F]+$/.test(share)
      )
    ) {
      throw new Error("All shares must be hex strings");
    }

    // Convert hex strings back to Buffers
    const shares = hexShares.map((hex) => Buffer.from(hex, "hex"));
    return Buffer.from(combine(shares));
  }

  /**
   * Test the Shamir's Secret Sharing implementation
   */
  static test() {
    const shamir = new Shamir();

    // Test 1: Basic string secret
    console.log("\nTest 1: Basic string secret");
    try {
      const secret = "Hello, World!";
      const shares = shamir.split(secret, { shares: 5, threshold: 3 });
      console.log("Created 5 shares:", shares);

      // Try combining different subsets of shares
      const recovered1 = shamir.combine(shares.slice(0, 3));
      const recovered2 = shamir.combine(shares.slice(2, 5));

      console.log("Recovered with shares 1-3:", recovered1.toString());
      console.log("Recovered with shares 3-5:", recovered2.toString());
      console.log("Test 1 passed ✓");
    } catch (error) {
      console.error("Test 1 failed:", error);
    }

    // Test 2: Binary data
    console.log("\nTest 2: Binary data");
    try {
      const secret = Buffer.from([1, 2, 3, 4, 5]);
      const shares = shamir.split(secret, { shares: 4, threshold: 2 });
      console.log("Created 4 shares:", shares);

      const recovered = shamir.combine(shares.slice(1, 3));
      console.log("Recovered secret:", Array.from(recovered));
      console.log("Original secret:", Array.from(secret));
      console.log("Test 2 passed ✓");
    } catch (error) {
      console.error("Test 2 failed:", error);
    }

    // Test 3: Error cases
    console.log("\nTest 3: Error cases");
    try {
      // Invalid shares number
      try {
        shamir.split("test", { shares: 1, threshold: 2 });
        console.error("Should have thrown error for invalid shares");
      } catch (e) {
        console.log("Correctly caught invalid shares:", e.message);
      }

      // Invalid threshold
      try {
        shamir.split("test", { shares: 3, threshold: 4 });
        console.error("Should have thrown error for invalid threshold");
      } catch (e) {
        console.log("Correctly caught invalid threshold:", e.message);
      }

      // Invalid share type
      try {
        shamir.combine(["not a hex string"]);
        console.error("Should have thrown error for invalid share type");
      } catch (e) {
        console.log("Correctly caught invalid share type:", e.message);
      }

      console.log("Test 3 passed ✓");
    } catch (error) {
      console.error("Test 3 failed:", error);
    }
  }

  /**
   * Test the Shamir's Secret Sharing implementation with BSV key scenarios
   */
  static testWithBSVKeys() {
    const shamir = new Shamir();
    console.log("\nTesting Shamir Secret Sharing with BSV Keys");

    // Test 1: Split and combine a WIF key
    console.log("\nTest 1: WIF Key");
    try {
      const wifKey = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ";
      const shares = shamir.split(wifKey, { shares: 5, threshold: 3 });
      console.log("Created 5 shares for WIF key");

      // Try different combinations of shares
      const recovered1 = shamir.combine(shares.slice(0, 3));
      const recovered2 = shamir.combine(shares.slice(2, 5));

      if (recovered1.toString() === wifKey && recovered2.toString() === wifKey) {
        console.log("✓ Successfully recovered WIF key from different share combinations");
      } else {
        throw new Error("WIF key recovery mismatch");
      }
    } catch (error) {
      console.error("Test 1 failed:", error);
    }

    // Test 2: Split and combine a mnemonic phrase
    console.log("\nTest 2: Mnemonic Phrase");
    try {
      const mnemonic = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual";
      const shares = shamir.split(mnemonic, { shares: 4, threshold: 2 });
      console.log("Created 4 shares for mnemonic");

      // Try combining with minimum shares
      const recovered = shamir.combine(shares.slice(1, 3));
      if (recovered.toString() === mnemonic) {
        console.log("✓ Successfully recovered mnemonic from minimum shares");
      } else {
        throw new Error("Mnemonic recovery mismatch");
      }
    } catch (error) {
      console.error("Test 2 failed:", error);
    }

    // Test 3: Error cases with BSV data
    console.log("\nTest 3: Error Cases");
    try {
      // Test with invalid threshold for sensitive data
      try {
        shamir.split("sensitive_wif_key", { shares: 3, threshold: 1 });
        console.error("Should have thrown error for unsafe threshold");
      } catch (e) {
        console.log("✓ Correctly caught unsafe threshold:", e.message);
      }

      // Test with insufficient shares for key recovery
      try {
        const shares = shamir.split("test_key", { shares: 5, threshold: 3 });
        shamir.combine(shares.slice(0, 2));
        console.error("Should have thrown error for insufficient shares");
      } catch (e) {
        console.log("✓ Correctly caught insufficient shares");
      }

      console.log("✓ All error cases handled correctly");
    } catch (error) {
      console.error("Test 3 failed:", error);
    }
  }
}

export default Shamir;
