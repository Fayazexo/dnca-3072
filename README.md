# DNCA3072

A dual-key encryption algorithm combining 3072-bit discrete logarithm cryptography with AES-GCM encryption.

## Features

- **Dual-key architecture**: Master keys generate encryption and decryption keys
- **AES-GCM encryption**: Industry-standard authenticated encryption
- **3072-bit security**: Equivalent to ~128-bit symmetric security
- **Key tracking**: Built-in audit trail for decryption operations
- **CLI interface**: Easy-to-use command-line tools

## Installation

```bash
npm install -g dnca
```

Or clone and install locally:
```bash
git clone <repository-url>
cd dnca
npm install
npm link
```

## Usage

### 1. Generate Master Key

```bash
dnca keygen -o master.key
```

### 2. Generate Encryption Key

```bash
dnca enckey -m master.key -o encryption.key
```

### 3. Generate Decryption Key

```bash
dnca deckey -m master.key -e encryption.key -o decryption.key
```

### 4. Encrypt Data

```bash
# Using master key
dnca encrypt -k master.key -i plaintext.txt -o encrypted.dat

# Using encryption key
dnca encrypt -k encryption.key -i plaintext.txt -o encrypted.dat

# From stdin to stdout
echo "secret message" | dnca encrypt -k encryption.key
```

### 5. Decrypt Data

```bash
# Using master key (can decrypt any encrypted data)
dnca decrypt -k master.key -i encrypted.dat -o decrypted.txt

# Using decryption key (only encryption-key encrypted data)
dnca decrypt -k decryption.key -i encrypted.dat -o decrypted.txt

# From stdin to stdout
cat encrypted.dat | dnca decrypt -k decryption.key
```

## Key Types

### Master Key
- Contains public/private key pair
- Can encrypt and decrypt any data
- Should be kept highly secure
- Used to generate other keys

### Encryption Key
- Derived from master key
- Used for encrypting data
- Can be distributed more freely
- Cannot decrypt data by itself

### Decryption Key
- Generated from master + encryption keys
- Can only decrypt data encrypted with corresponding encryption key
- Contains unique tracking ID
- Provides audit trail

## Security Features

1. **Authentication**: All encrypted data includes authentication tags
2. **Tamper Detection**: Modified ciphertext will fail decryption
3. **Key Isolation**: Decryption keys can't decrypt master-key encrypted data
4. **Audit Trail**: Tracking information included in decryption results
5. **Forward Security**: Each decryption key is unique with timestamps

## Programmatic API Usage

### Installation for Projects

```bash
npm install dnca
```

### JavaScript Usage

```javascript
const DNCA3072 = require('dnca');

async function example() {
    const dnca = new DNCA3072();
    
    // Generate keys
    const masterKey = await dnca.generateMasterKey();
    const encryptionKey = await dnca.generateEncryptionKey(masterKey);
    const decryptionKey = await dnca.generateDecryptionKey(masterKey, encryptionKey);
    
    // Encrypt data
    const encrypted = await dnca.encrypt("Hello World", encryptionKey);
    
    // Decrypt data
    const result = await dnca.decrypt(encrypted, decryptionKey);
    console.log(result.plaintext); // "Hello World"
    console.log(result.trackingInfo); // Audit information
}

example();
```

### TypeScript Usage

```typescript
import DNCA3072, { MasterKey, EncryptionKey, DecryptionKey } from 'dnca';

async function example(): Promise<void> {
    const dnca = new DNCA3072();
    
    // Generate keys with proper typing
    const masterKey: MasterKey = await dnca.generateMasterKey();
    const encryptionKey: EncryptionKey = await dnca.generateEncryptionKey(masterKey);
    const decryptionKey: DecryptionKey = await dnca.generateDecryptionKey(masterKey, encryptionKey);
    
    // Encrypt data
    const encrypted: string = await dnca.encrypt("Hello World", encryptionKey);
    
    // Decrypt data with full type safety
    const result = await dnca.decrypt(encrypted, decryptionKey);
    console.log(result.plaintext); // "Hello World"
    console.log(result.trackingInfo); // Audit information
}

example();
```

**TypeScript Features:**
- **Full type safety**: All interfaces and types exported
- **IntelliSense support**: IDE autocompletion and error checking
- **Strict typing**: BigInt types for cryptographic keys
- **Comprehensive interfaces**: `MasterKey`, `EncryptionKey`, `DecryptionKey`, `EncryptedData`, `DecryptionResult`

### Complete API Reference

#### Key Generation

```javascript
// Generate master key pair
const masterKey = await dnca.generateMasterKey();
// Returns: { private: BigInt, public: BigInt, type: 'master' }

// Generate encryption key from master key
const encryptionKey = await dnca.generateEncryptionKey(masterKey);
// Returns: { key: BigInt, masterPublic: BigInt, type: 'encryption' }

// Generate decryption key
const decryptionKey = await dnca.generateDecryptionKey(masterKey, encryptionKey);
// Returns: { key: BigInt, keyId: string, encryptionKeyHash: BigInt, masterPublic: BigInt, type: 'decryption' }
```

#### Encryption

```javascript
// Encrypt with master key (can be decrypted by master key only)
const masterEncrypted = await dnca.encrypt(plaintext, masterKey);

// Encrypt with encryption key (can be decrypted by master or decryption keys)
const encKeyEncrypted = await dnca.encrypt(plaintext, encryptionKey);

// Both return JSON string with Base64-encoded data:
// { ciphertext, iv, nonce, keyType, timestamp, authTag, publicKey }
```

#### Decryption

```javascript
// Decrypt with master key (can decrypt any data)
const masterResult = await dnca.decryptWithMaster(encrypted, masterKey);

// Decrypt with decryption key (only encryption-key encrypted data)
const decResult = await dnca.decrypt(encrypted, decryptionKey);

// Both return:
// {
//   plaintext: string,
//   trackingInfo: {
//     decryptedBy: string,
//     decryptedAt: string,
//     originalEncryption: { timestamp: string, keyType: string }
//   }
// }
```

#### Utility Functions

```javascript
// Generate secure random BigInt
const randomValue = dnca.generateSecureRandom(256); // 256 bits

// Hash data with SHA-256
const hash = await dnca.customHash("data to hash");

// Derive key from secret + salt + info
const derivedKey = await dnca.deriveKey(secret, "salt", "INFO");

// Modular exponentiation
const result = dnca.modPow(base, exponent, modulus);
```

#### Error Handling

```javascript
try {
    const result = await dnca.decrypt(tamperedData, decryptionKey);
} catch (error) {
    if (error.message.includes('Authentication failed')) {
        console.log('Data has been tampered with');
    } else if (error.message.includes('Cannot decrypt master-key-encrypted')) {
        console.log('Wrong key type for this encrypted data');
    }
}
```

### Key Features for Developers

- **TypeScript-first**: Written in TypeScript with full type definitions
- **Type safety**: Complete interfaces for all key types and operations
- **Memory-safe**: No key material stored in strings, BigInt for crypto values
- **Base64 encoding**: Full alphanumeric character set
- **Authentication**: Built-in tamper detection with AES-GCM
- **Audit trail**: Comprehensive tracking information
- **Error handling**: Clear, actionable error messages with proper typing
- **Performance logging**: Detailed timing information for all operations

### Example Project Integration

```javascript
// config.js
const DNCA3072 = require('dnca');
const fs = require('fs').promises;

class SecureConfig {
    constructor() {
        this.dnca = new DNCA3072();
    }
    
    async loadKeys() {
        try {
            const masterData = await fs.readFile('keys/master.key', 'utf8');
            this.masterKey = JSON.parse(masterData, (key, value) => {
                if (key === 'private' || key === 'public') {
                    const bytes = Buffer.from(value, 'base64');
                    return BigInt('0x' + bytes.toString('hex'));
                }
                return value;
            });
        } catch (error) {
            console.log('Generating new master key...');
            this.masterKey = await this.dnca.generateMasterKey();
            await this.saveKey('keys/master.key', this.masterKey);
        }
    }
    
    async encryptSecret(data) {
        return await this.dnca.encrypt(data, this.masterKey);
    }
    
    async decryptSecret(encrypted) {
        const result = await this.dnca.decryptWithMaster(encrypted, this.masterKey);
        return result.plaintext;
    }
}

module.exports = SecureConfig;
```

## Commands

| Command | Description | Options |
|---------|-------------|---------|
| `keygen` | Generate master key | `-o, --output <file>` |
| `enckey` | Generate encryption key | `-m, --master <file>`, `-o, --output <file>` |
| `deckey` | Generate decryption key | `-m, --master <file>`, `-e, --encryption <file>`, `-o, --output <file>` |
| `encrypt` | Encrypt data | `-k, --key <file>`, `-i, --input <file>`, `-o, --output <file>` |
| `decrypt` | Decrypt data | `-k, --key <file>`, `-i, --input <file>`, `-o, --output <file>` |

## Security Considerations

- **Keep master keys secure**: They have full access to all encrypted data
- **Distribute encryption keys safely**: They enable data encryption
- **Monitor decryption keys**: Each has unique tracking for audit purposes
- **Verify integrity**: Always check authentication during decryption
- **Use secure storage**: Keys should be stored with appropriate file permissions

## License

MIT

## Contributing

Please read the contributing guidelines before submitting pull requests.