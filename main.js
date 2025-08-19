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
		const bytes = bits / 8;
		const array = new Uint8Array(bytes);
		crypto.getRandomValues(array);
		return BigInt(
			"0x" +
				Array.from(array)
					.map((b) => b.toString(16).padStart(2, "0"))
					.join("")
		);
	}

	async customHash(data) {
		const encoder = new TextEncoder();
		const dataBuffer = encoder.encode(data);
		const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
		const hashArray = new Uint8Array(hashBuffer);
		return BigInt(
			"0x" +
				Array.from(hashArray)
					.map((b) => b.toString(16).padStart(2, "0"))
					.join("")
		);
	}

	async deriveKey(secret, salt, info) {
		const combined = secret.toString(16) + salt + info;
		const hash = await this.customHash(combined);
		return (hash % (this.PRIME - BigInt(1))) + BigInt(1);
	}

	async generateMasterKey() {
		const privateKey = this.generateSecureRandom(256);
		const publicKey = this.modPow(this.GENERATOR, privateKey, this.PRIME);

		return {
			private: privateKey,
			public: publicKey,
			type: "master",
		};
	}

	async generateEncryptionKey(masterKey) {
		if (masterKey.type !== "master") {
			throw new Error("Invalid master key");
		}

		const encryptionKey = await this.deriveKey(
			masterKey.private,
			"",
			"ENCRYPT"
		);
		return {
			key: encryptionKey,
			masterPublic: masterKey.public,
			type: "encryption",
		};
	}

	async generateDecryptionKey(masterKey, encryptionKey) {
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

		return {
			key: decryptionSecret,
			keyId: keyId,
			encryptionKeyHash: await this.customHash(encryptionKey.key.toString()),
			masterPublic: masterKey.public,
			type: "decryption",
		};
	}

	modPow(base, exponent, modulus) {
		let result = BigInt(1);
		base = base % modulus;

		while (exponent > 0) {
			if (exponent % BigInt(2) === BigInt(1)) {
				result = (result * base) % modulus;
			}
			exponent = exponent >> BigInt(1);
			base = (base * base) % modulus;
		}

		return result;
	}

	xorWithKey(data, key, nonce) {
		const combined = key + nonce;
		const keyStream = combined.toString(16);
		const result = [];

		for (let i = 0; i < data.length; i++) {
			const keyByte =
				parseInt(
					keyStream.charAt(i % keyStream.length) +
						keyStream.charAt((i + 1) % keyStream.length),
					16
				) || 1;
			result.push(data.charCodeAt(i) ^ keyByte);
		}

		return String.fromCharCode(...result);
	}

	async encrypt(plaintext, key) {
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

		const ciphertext = this.xorWithKey(plaintext, encryptionKey, nonce);

		const authData =
			ciphertext + nonce.toString(16) + keyTypeFlag + timestamp.toString(16);
		const authTag = await this.customHash(
			authData + encryptionKey.toString(16)
		);

		const result = {
			ciphertext: btoa(ciphertext),
			nonce: nonce.toString(16),
			keyType: keyTypeFlag,
			timestamp: timestamp.toString(16),
			authTag: authTag.toString(16),
			publicKey:
				key.type === "master"
					? key.public.toString(16)
					: key.masterPublic.toString(16),
		};

		return JSON.stringify(result);
	}

	async decrypt(encryptedData, decryptionKey) {
		const time = performance.now();
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

		const authData =
			atob(data.ciphertext) + data.nonce + data.keyType + data.timestamp;
		const expectedAuthTag = await this.customHash(
			authData + originalEncKey.toString(16)
		);

		if (expectedAuthTag.toString(16) !== data.authTag) {
			throw new Error("Authentication failed - data may be tampered");
		}

		const nonce = BigInt("0x" + data.nonce);
		const plaintext = this.xorWithKey(
			atob(data.ciphertext),
			originalEncKey,
			nonce
		);

		console.log("Decryption Time:", performance.now() - time, "ms");

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
		const time = performance.now();
		if (masterKey.type !== "master") {
			throw new Error("Invalid master key");
		}

		const data = JSON.parse(encryptedData);

		console.log("Decryption Data:", data);

		let decryptionKey;
		if (data.keyType === "1") {
			decryptionKey = masterKey.private;
		} else {
			decryptionKey = await this.deriveKey(masterKey.private, "", "ENCRYPT");
		}

		const authData =
			atob(data.ciphertext) + data.nonce + data.keyType + data.timestamp;
		const expectedAuthTag = await this.customHash(
			authData + decryptionKey.toString(16)
		);

		if (expectedAuthTag.toString(16) !== data.authTag) {
			throw new Error("Authentication failed - data may be tampered");
		}

		const nonce = BigInt("0x" + data.nonce);
		const plaintext = this.xorWithKey(
			atob(data.ciphertext),
			decryptionKey,
			nonce
		);
		console.log("Decryption Time:", performance.now() - time, "ms");

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
		const keyIdHash = await this.customHash(decryptionKey.keyId);
		return (decryptionKey.key - keyIdHash) % this.PRIME;
	}
}
