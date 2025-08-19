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

## API Usage

```javascript
const DNCA3072 = require('dnca');

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