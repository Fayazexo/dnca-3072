/**
 * DNCA3072 - Dual-key encryption algorithm with AES-GCM and 3072-bit prime modulus
 */

// Type definitions
export interface MasterKey {
  private: bigint;
  public: bigint;
  type: 'master';
}

export interface EncryptionKey {
  key: bigint;
  masterPublic: bigint;
  type: 'encryption';
}

export interface DecryptionKey {
  key: bigint;
  keyId: string;
  encryptionKey: bigint;
  encryptionKeyHash: bigint;
  masterPublic: bigint;
  type: 'decryption';
}

export type DNCAKey = MasterKey | EncryptionKey | DecryptionKey;

export interface EncryptedData {
  ciphertext: string;
  iv: string;
  nonce: string;
  keyType: string;
  timestamp: string;
  authTag: string;
  publicKey: string;
}

export interface DecryptionResult {
  plaintext: string;
  trackingInfo: {
    decryptedBy: string;
    decryptedAt: string;
    originalEncryption: {
      timestamp: string;
      keyType: string;
    };
  };
}

export interface AESResult {
  ciphertext: Uint8Array;
  iv: Uint8Array;
}

export default class DNCA3072 {
  private readonly PRIME: bigint;
  private readonly GENERATOR: bigint;
  private keyCounter: number;

  constructor() {
    this.PRIME = BigInt(
      "0x" +
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    );

    this.GENERATOR = BigInt(2);
    this.keyCounter = 0;
  }

  /**
   * Generates a cryptographically secure random BigInt
   * @param bits - Number of bits for the random value (default: 256)
   * @returns A secure random BigInt
   */
  generateSecureRandom(bits: number = 256): bigint {
    const startTime = performance.now();
    const bytes = bits / 8;
    const array = new Uint8Array(bytes);
    crypto.getRandomValues(array);
    const result = BigInt(
      "0x" +
        Array.from(array)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("")
    );
    const endTime = performance.now();
    console.error(`Secure random generation (${bits} bits): ${(endTime - startTime).toFixed(3)}ms`);
    return result;
  }

  /**
   * Computes SHA-256 hash of input data
   * @param data - String data to hash
   * @returns BigInt representation of the hash
   */
  async customHash(data: string): Promise<bigint> {
    const startTime = performance.now();
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
    const hashArray = new Uint8Array(hashBuffer);
    const result = BigInt(
      "0x" +
        Array.from(hashArray)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("")
    );
    const endTime = performance.now();
    console.error(`SHA-256 hash: ${(endTime - startTime).toFixed(3)}ms`);
    return result;
  }

  /**
   * Derives a key from secret, salt, and info using SHA-256
   * @param secret - Secret value (BigInt)
   * @param salt - Salt string
   * @param info - Info/context string
   * @returns Derived key as BigInt
   */
  async deriveKey(secret: bigint, salt: string, info: string): Promise<bigint> {
    const startTime = performance.now();
    const combined = secret.toString(16) + salt + info;
    const hash = await this.customHash(combined);
    const result = (hash % (this.PRIME - BigInt(1))) + BigInt(1);
    const endTime = performance.now();
    console.error(`Key derivation: ${(endTime - startTime).toFixed(3)}ms`);
    return result;
  }

  /**
   * Generates a master key pair
   * @returns Master key object with private and public keys
   */
  async generateMasterKey(): Promise<MasterKey> {
    const startTime = performance.now();
    const privateKey = this.generateSecureRandom(256);
    const publicKey = this.modPow(this.GENERATOR, privateKey, this.PRIME);
    const endTime = performance.now();
    console.error(`Master key generation: ${(endTime - startTime).toFixed(3)}ms`);

    return {
      private: privateKey,
      public: publicKey,
      type: "master",
    };
  }

  /**
   * Generates an encryption key from a master key
   * @param masterKey - Master key to derive from
   * @returns Encryption key object
   */
  async generateEncryptionKey(masterKey: MasterKey): Promise<EncryptionKey> {
    const startTime = performance.now();
    if (masterKey.type !== "master") {
      throw new Error("Invalid master key");
    }

    const encryptionKey = await this.deriveKey(
      masterKey.private,
      "",
      "ENCRYPT"
    );
    const endTime = performance.now();
    console.error(`Encryption key generation: ${(endTime - startTime).toFixed(3)}ms`);
    return {
      key: encryptionKey,
      masterPublic: masterKey.public,
      type: "encryption",
    };
  }

  /**
   * Generates a decryption key from master and encryption keys
   * @param masterKey - Master key
   * @param encryptionKey - Encryption key
   * @returns Decryption key object
   */
  async generateDecryptionKey(masterKey: MasterKey, encryptionKey: EncryptionKey): Promise<DecryptionKey> {
    const startTime = performance.now();
    if (masterKey.type !== "master" || encryptionKey.type !== "encryption") {
      throw new Error("Invalid keys provided");
    }

    this.keyCounter++;
    const keyId = `DK_${Date.now()}_${this.keyCounter}`;
    const salt = keyId;

    const decryptionSecret = await this.deriveKey(
      masterKey.private + encryptionKey.key,
      salt,
      "DECRYPT"
    );
    const endTime = performance.now();
    console.error(`Decryption key generation: ${(endTime - startTime).toFixed(3)}ms`);

    return {
      key: decryptionSecret,
      keyId: keyId,
      encryptionKey: encryptionKey.key,
      encryptionKeyHash: await this.customHash(encryptionKey.key.toString()),
      masterPublic: masterKey.public,
      type: "decryption",
    };
  }

  /**
   * Performs modular exponentiation: (base^exponent) mod modulus
   * @param base - Base value
   * @param exponent - Exponent value  
   * @param modulus - Modulus value
   * @returns Result of modular exponentiation
   */
  modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
    const startTime = performance.now();
    let result = BigInt(1);
    base = base % modulus;

    while (exponent > 0) {
      if (exponent % BigInt(2) === BigInt(1)) {
        result = (result * base) % modulus;
      }
      exponent = exponent >> BigInt(1);
      base = (base * base) % modulus;
    }
    const endTime = performance.now();
    console.error(`Modular exponentiation: ${(endTime - startTime).toFixed(3)}ms`);
    return result;
  }

  /**
   * Derives AES key from encryption key and nonce
   * @param key - Encryption key
   * @param nonce - Nonce value
   * @returns AES CryptoKey for encryption/decryption
   */
  async deriveAESKey(key: bigint, nonce: bigint): Promise<CryptoKey> {
    const keyMaterial = key.toString(16) + nonce.toString(16);
    const keyHash = await this.customHash(keyMaterial);
    const keyBytes = new Uint8Array(32);

    const keyHex = keyHash.toString(16).padStart(64, "0");
    for (let i = 0; i < 32; i++) {
      keyBytes[i] = parseInt(keyHex.substring(i * 2, i * 2 + 2), 16);
    }

    return await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Encrypts plaintext using AES-GCM
   * @param plaintext - Text to encrypt
   * @param key - Encryption key
   * @param nonce - Nonce value
   * @returns Encrypted data with IV
   */
  async encryptWithAES(plaintext: string, key: bigint, nonce: bigint): Promise<AESResult> {
    const aesKey = await this.deriveAESKey(key, nonce);
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength) as ArrayBuffer },
      aesKey,
      data
    );

    return {
      ciphertext: new Uint8Array(encrypted),
      iv: iv,
    };
  }

  /**
   * Decrypts ciphertext using AES-GCM
   * @param ciphertext - Encrypted data
   * @param key - Decryption key
   * @param nonce - Nonce value
   * @param iv - Initialization vector
   * @returns Decrypted plaintext
   */
  async decryptWithAES(ciphertext: Uint8Array, key: bigint, nonce: bigint, iv: Uint8Array): Promise<string> {
    const aesKey = await this.deriveAESKey(key, nonce);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength) as ArrayBuffer },
      aesKey,
      ciphertext.buffer.slice(ciphertext.byteOffset, ciphertext.byteOffset + ciphertext.byteLength) as ArrayBuffer
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }

  /**
   * Encrypts plaintext with the provided key
   * @param plaintext - Text to encrypt
   * @param key - Master or encryption key
   * @returns JSON string of encrypted data
   */
  async encrypt(plaintext: string, key: MasterKey | EncryptionKey): Promise<string> {
    const startTime = performance.now();
    const nonce = this.generateSecureRandom(128);
    const timestamp = BigInt(Date.now());

    let encryptionKey: bigint;
    let keyTypeFlag: string;

    if (key.type === "master") {
      encryptionKey = key.private;
      keyTypeFlag = "1";
    } else if (key.type === "encryption") {
      encryptionKey = key.key;
      keyTypeFlag = "0";
    } else {
      throw new Error("Invalid key type for encryption");
    }

    const encrypted = await this.encryptWithAES(
      plaintext,
      encryptionKey,
      nonce
    );

    const authData = Buffer.concat([
      Buffer.from(encrypted.ciphertext),
      Buffer.from(
        nonce
          .toString(16)
          .padStart(32, "0")
          .match(/.{2}/g)!
          .map((byte) => parseInt(byte, 16))
      ),
      Buffer.from(keyTypeFlag),
      Buffer.from(
        timestamp
          .toString(16)
          .padStart(16, "0")
          .match(/.{2}/g)!
          .map((byte) => parseInt(byte, 16))
      ),
    ]).toString("hex");
    const authTag = await this.customHash(
      authData + encryptionKey.toString(16)
    );

    const result: EncryptedData = {
      ciphertext: Buffer.from(encrypted.ciphertext).toString("base64"),
      iv: Buffer.from(encrypted.iv).toString("base64"),
      nonce: Buffer.from(
        nonce
          .toString(16)
          .padStart(32, "0")
          .match(/.{2}/g)!
          .map((byte) => parseInt(byte, 16))
      ).toString("base64"),
      keyType: keyTypeFlag,
      timestamp: Buffer.from(
        timestamp
          .toString(16)
          .padStart(16, "0")
          .match(/.{2}/g)!
          .map((byte) => parseInt(byte, 16))
      ).toString("base64"),
      authTag: Buffer.from(
        authTag
          .toString(16)
          .padStart(64, "0")
          .match(/.{2}/g)!
          .map((byte) => parseInt(byte, 16))
      ).toString("base64"),
      publicKey: Buffer.from(
        (key.type === "master" ? key.public : key.masterPublic)
          .toString(16)
          .padStart(768, "0")
          .match(/.{2}/g)!
          .map((byte) => parseInt(byte, 16))
      ).toString("base64"),
    };

    const endTime = performance.now();
    console.error(`Encryption: ${(endTime - startTime).toFixed(3)}ms`);
    return JSON.stringify(result);
  }

  /**
   * Decrypts data using a decryption key
   * @param encryptedData - JSON string of encrypted data
   * @param decryptionKey - Decryption key
   * @returns Decryption result with plaintext and tracking info
   */
  async decrypt(encryptedData: string, decryptionKey: DecryptionKey): Promise<DecryptionResult> {
    const startTime = performance.now();
    if (decryptionKey.type !== "decryption") {
      throw new Error("Invalid decryption key");
    }

    const data: EncryptedData = JSON.parse(encryptedData);

    if (data.keyType === "1") {
      throw new Error(
        "Cannot decrypt master-key-encrypted data with decryption key"
      );
    }

    const originalEncKey = await this.deriveOriginalEncryptionKey(
      decryptionKey
    );

    const ciphertextBytes = Buffer.from(data.ciphertext, "base64");
    const nonceBytes = Buffer.from(data.nonce, "base64");
    const timestampBytes = Buffer.from(data.timestamp, "base64");
    const authData = Buffer.concat([
      ciphertextBytes,
      nonceBytes,
      Buffer.from(data.keyType),
      timestampBytes,
    ]).toString("hex");
    const expectedAuthTag = await this.customHash(
      authData + originalEncKey.toString(16)
    );

    if (
      expectedAuthTag.toString(16) !==
      Buffer.from(data.authTag, "base64").toString("hex")
    ) {
      throw new Error("Authentication failed - data may be tampered");
    }

    const nonce = BigInt("0x" + nonceBytes.toString("hex"));
    const ciphertext = new Uint8Array(ciphertextBytes);
    const iv = new Uint8Array(Buffer.from(data.iv, "base64"));
    const plaintext = await this.decryptWithAES(
      ciphertext,
      originalEncKey,
      nonce,
      iv
    );

    const endTime = performance.now();
    console.error(`Decryption (with decryption key): ${(endTime - startTime).toFixed(3)}ms`);
    return {
      plaintext: plaintext,
      trackingInfo: {
        decryptedBy: decryptionKey.keyId,
        decryptedAt: new Date().toISOString(),
        originalEncryption: {
          timestamp: new Date(parseInt(Buffer.from(data.timestamp, 'base64').toString('hex'), 16)).toISOString(),
          keyType: data.keyType === "0" ? "encryption" : "master",
        },
      },
    };
  }

  /**
   * Decrypts data using a master key
   * @param encryptedData - JSON string of encrypted data
   * @param masterKey - Master key
   * @returns Decryption result with plaintext and tracking info
   */
  async decryptWithMaster(encryptedData: string, masterKey: MasterKey): Promise<DecryptionResult> {
    const startTime = performance.now();
    if (masterKey.type !== "master") {
      throw new Error("Invalid master key");
    }

    const data: EncryptedData = JSON.parse(encryptedData);

    let decryptionKey: bigint;
    if (data.keyType === "1") {
      decryptionKey = masterKey.private;
    } else {
      decryptionKey = await this.deriveKey(masterKey.private, "", "ENCRYPT");
    }

    const ciphertextBytes = Buffer.from(data.ciphertext, "base64");
    const nonceBytes = Buffer.from(data.nonce, "base64");
    const timestampBytes = Buffer.from(data.timestamp, "base64");
    const authData = Buffer.concat([
      ciphertextBytes,
      nonceBytes,
      Buffer.from(data.keyType),
      timestampBytes,
    ]).toString("hex");
    const expectedAuthTag = await this.customHash(
      authData + decryptionKey.toString(16)
    );

    if (
      expectedAuthTag.toString(16) !==
      Buffer.from(data.authTag, "base64").toString("hex")
    ) {
      throw new Error("Authentication failed - data may be tampered");
    }

    const nonce = BigInt("0x" + nonceBytes.toString("hex"));
    const ciphertext = new Uint8Array(ciphertextBytes);
    const iv = new Uint8Array(Buffer.from(data.iv, "base64"));
    const plaintext = await this.decryptWithAES(
      ciphertext,
      decryptionKey,
      nonce,
      iv
    );

    const endTime = performance.now();
    console.error(`Decryption (with master key): ${(endTime - startTime).toFixed(3)}ms`);
    return {
      plaintext: plaintext,
      trackingInfo: {
        decryptedBy: "MASTER_KEY",
        decryptedAt: new Date().toISOString(),
        originalEncryption: {
          timestamp: new Date(parseInt(Buffer.from(data.timestamp, 'base64').toString('hex'), 16)).toISOString(),
          keyType: data.keyType === "0" ? "encryption" : "master",
        },
      },
    };
  }

  /**
   * Derives the original encryption key from a decryption key
   * @param decryptionKey - Decryption key containing the encryption key
   * @returns Original encryption key
   */
  async deriveOriginalEncryptionKey(decryptionKey: DecryptionKey): Promise<bigint> {
    // Return the stored encryption key from the decryption key
    return decryptionKey.encryptionKey;
  }
}

// CommonJS export for backwards compatibility
module.exports = DNCA3072;