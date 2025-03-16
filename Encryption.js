// Encryption.js crypto-js
import CryptoJS from "crypto-js";

export const encrypt = (text, key) => {
  return CryptoJS.AES.encrypt(text, key).toString();
};

export const decrypt = (encryptedText, key) => {
  const bytes = CryptoJS.AES.decrypt(encryptedText, key);
  return bytes.toString(CryptoJS.enc.Utf8);
};

export const encryptObject = (obj, key) => {
  return encrypt(JSON.stringify(obj), key);
};

export const decryptObject = (encryptedText, key) => {
  const decryptedText = decrypt(encryptedText, key);
  return JSON.parse(decryptedText);
};

// Usage
// const encrypted = encrypt("Hello, World!", "my-secret-key");
// const decrypted = decrypt(encrypted, "my-secret-key");
// console.log(decrypted); // Hello, World!

// const encryptedObject = encryptObject(
//   { name: "John", age: 30 },
//   "my-secret-key"
// );
// const decryptedObject = decryptObject(encryptedObject, "my-secret-key");
// console.log(decryptedObject); // { name: "John", age: 30 }
