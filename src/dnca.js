class DNCA3072 {
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

	generateSecureRandom(bits = 256) {
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

	async customHash(data) {
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

	async deriveKey(secret, salt, info) {
		const startTime = performance.now();
		const combined = secret.toString(16) + salt + info;
		const hash = await this.customHash(combined);
		const result = (hash % (this.PRIME - BigInt(1))) + BigInt(1);
		const endTime = performance.now();
		console.error(`Key derivation: ${(endTime - startTime).toFixed(3)}ms`);
		return result;
	}

	async generateMasterKey() {
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

	async generateEncryptionKey(masterKey) {
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

	async generateDecryptionKey(masterKey, encryptionKey) {
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

	modPow(base, exponent, modulus) {
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

	async deriveAESKey(key, nonce) {
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

	async encryptWithAES(plaintext, key, nonce) {
		const aesKey = await this.deriveAESKey(key, nonce);
		const encoder = new TextEncoder();
		const data = encoder.encode(plaintext);

		const iv = new Uint8Array(12);
		crypto.getRandomValues(iv);

		const encrypted = await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: iv },
			aesKey,
			data
		);

		return {
			ciphertext: new Uint8Array(encrypted),
			iv: iv,
		};
	}

	async decryptWithAES(ciphertext, key, nonce, iv) {
		const aesKey = await this.deriveAESKey(key, nonce);

		const decrypted = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: iv },
			aesKey,
			ciphertext
		);

		const decoder = new TextDecoder();
		return decoder.decode(decrypted);
	}

	async encrypt(plaintext, key) {
		const startTime = performance.now();
		const nonce = this.generateSecureRandom(128);
		const timestamp = BigInt(Date.now());

		let encryptionKey, keyTypeFlag;

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
					.match(/.{2}/g)
					.map((byte) => parseInt(byte, 16))
			),
			Buffer.from(keyTypeFlag),
			Buffer.from(
				timestamp
					.toString(16)
					.padStart(16, "0")
					.match(/.{2}/g)
					.map((byte) => parseInt(byte, 16))
			),
		]).toString("hex");
		const authTag = await this.customHash(
			authData + encryptionKey.toString(16)
		);

		const result = {
			ciphertext: Buffer.from(encrypted.ciphertext).toString("base64"),
			iv: Buffer.from(encrypted.iv).toString("base64"),
			nonce: Buffer.from(
				nonce
					.toString(16)
					.padStart(32, "0")
					.match(/.{2}/g)
					.map((byte) => parseInt(byte, 16))
			).toString("base64"),
			keyType: keyTypeFlag,
			timestamp: Buffer.from(
				timestamp
					.toString(16)
					.padStart(16, "0")
					.match(/.{2}/g)
					.map((byte) => parseInt(byte, 16))
			).toString("base64"),
			authTag: Buffer.from(
				authTag
					.toString(16)
					.padStart(64, "0")
					.match(/.{2}/g)
					.map((byte) => parseInt(byte, 16))
			).toString("base64"),
			publicKey: Buffer.from(
				(key.type === "master" ? key.public : key.masterPublic)
					.toString(16)
					.padStart(768, "0")
					.match(/.{2}/g)
					.map((byte) => parseInt(byte, 16))
			).toString("base64"),
		};

		const endTime = performance.now();
		console.error(`Encryption: ${(endTime - startTime).toFixed(3)}ms`);
		return JSON.stringify(result);
	}

	async decrypt(encryptedData, decryptionKey) {
		const startTime = performance.now();
		if (decryptionKey.type !== "decryption") {
			throw new Error("Invalid decryption key");
		}

		const data = JSON.parse(encryptedData);

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
					timestamp: new Date(parseInt(data.timestamp, 16)).toISOString(),
					keyType: data.keyType === "0" ? "encryption" : "master",
				},
			},
		};
	}

	async decryptWithMaster(encryptedData, masterKey) {
		const startTime = performance.now();
		if (masterKey.type !== "master") {
			throw new Error("Invalid master key");
		}

		const data = JSON.parse(encryptedData);

		let decryptionKey;
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
					timestamp: new Date(parseInt(data.timestamp, 16)).toISOString(),
					keyType: data.keyType === "0" ? "encryption" : "master",
				},
			},
		};
	}

	async deriveOriginalEncryptionKey(decryptionKey) {
		// Return the stored encryption key from the decryption key
		return decryptionKey.encryptionKey;
	}
}

module.exports = DNCA3072;
