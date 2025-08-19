import DNCA3072, { MasterKey, EncryptionKey, DecryptionKey } from './src/dnca';

async function demonstrateAPI(): Promise<void> {
    console.log('🔐 DNCA3072 API Demonstration\n');
    
    // Initialize DNCA3072 instance
    const dnca = new DNCA3072();
    
    try {
        // 1. Generate Master Key
        console.log('1️⃣ Generating Master Key...');
        const masterKey: MasterKey = await dnca.generateMasterKey();
        console.log('✅ Master key generated');
        console.log('   Type:', masterKey.type);
        console.log('   Has private key:', typeof masterKey.private === 'bigint');
        console.log('   Has public key:', typeof masterKey.public === 'bigint');
        console.log();
        
        // 2. Generate Encryption Key
        console.log('2️⃣ Generating Encryption Key...');
        const encryptionKey: EncryptionKey = await dnca.generateEncryptionKey(masterKey);
        console.log('✅ Encryption key generated');
        console.log('   Type:', encryptionKey.type);
        console.log('   Key length:', encryptionKey.key.toString(16).length, 'hex chars');
        console.log();
        
        // 3. Generate Decryption Key
        console.log('3️⃣ Generating Decryption Key...');
        const decryptionKey: DecryptionKey = await dnca.generateDecryptionKey(masterKey, encryptionKey);
        console.log('✅ Decryption key generated');
        console.log('   Type:', decryptionKey.type);
        console.log('   Key ID:', decryptionKey.keyId);
        console.log();
        
        // 4. Encrypt with Master Key
        const testMessage = 'Hello DNCA3072! This is a test message with special chars: @#$%^&*()_+{}[]|;:,.<>?';
        console.log('4️⃣ Encrypting with Master Key...');
        const masterEncrypted: string = await dnca.encrypt(testMessage, masterKey);
        console.log('✅ Encrypted with master key');
        const masterData = JSON.parse(masterEncrypted);
        console.log('   Ciphertext length:', masterData.ciphertext.length);
        console.log('   Key type:', masterData.keyType === '1' ? 'Master' : 'Encryption');
        console.log();
        
        // 5. Encrypt with Encryption Key
        console.log('5️⃣ Encrypting with Encryption Key...');
        const encKeyEncrypted: string = await dnca.encrypt(testMessage, encryptionKey);
        console.log('✅ Encrypted with encryption key');
        const encData = JSON.parse(encKeyEncrypted);
        console.log('   Ciphertext length:', encData.ciphertext.length);
        console.log('   Key type:', encData.keyType === '0' ? 'Encryption' : 'Master');
        console.log();
        
        // 6. Decrypt with Master Key
        console.log('6️⃣ Decrypting with Master Key...');
        const masterDecrypted1 = await dnca.decryptWithMaster(masterEncrypted, masterKey);
        const masterDecrypted2 = await dnca.decryptWithMaster(encKeyEncrypted, masterKey);
        console.log('✅ Master key can decrypt both:');
        console.log('   Master-encrypted:', masterDecrypted1.plaintext === testMessage ? '✅' : '❌');
        console.log('   Enc-key-encrypted:', masterDecrypted2.plaintext === testMessage ? '✅' : '❌');
        console.log('   Decrypted by:', masterDecrypted1.trackingInfo.decryptedBy);
        console.log();
        
        // 7. Decrypt with Decryption Key
        console.log('7️⃣ Decrypting with Decryption Key...');
        try {
            await dnca.decrypt(masterEncrypted, decryptionKey);
            console.log('❌ Should not be able to decrypt master-encrypted data');
        } catch (error) {
            console.log('✅ Correctly blocked master-encrypted data:', (error as Error).message.substring(0, 50) + '...');
        }
        
        const decKeyDecrypted = await dnca.decrypt(encKeyEncrypted, decryptionKey);
        console.log('✅ Decryption key can decrypt enc-key data:', decKeyDecrypted.plaintext === testMessage ? '✅' : '❌');
        console.log('   Decrypted by:', decKeyDecrypted.trackingInfo.decryptedBy);
        console.log();
        
        // 8. Key Derivation Functions
        console.log('8️⃣ Testing Key Derivation...');
        const derived1: bigint = await dnca.deriveKey(masterKey.private, 'salt123', 'TEST');
        const derived2: bigint = await dnca.deriveKey(masterKey.private, 'salt123', 'TEST');
        const derived3: bigint = await dnca.deriveKey(masterKey.private, 'salt456', 'TEST');
        console.log('✅ Key derivation deterministic:', derived1 === derived2 ? '✅' : '❌');
        console.log('✅ Different salt produces different key:', derived1 !== derived3 ? '✅' : '❌');
        console.log();
        
        // 9. Cryptographic Primitives
        console.log('9️⃣ Testing Cryptographic Primitives...');
        const random1: bigint = dnca.generateSecureRandom(256);
        const random2: bigint = dnca.generateSecureRandom(256);
        console.log('✅ Secure random generates different values:', random1 !== random2 ? '✅' : '❌');
        
        const hash1: bigint = await dnca.customHash('test data');
        const hash2: bigint = await dnca.customHash('test data');
        const hash3: bigint = await dnca.customHash('different data');
        console.log('✅ Hash function deterministic:', hash1 === hash2 ? '✅' : '❌');
        console.log('✅ Different inputs produce different hashes:', hash1 !== hash3 ? '✅' : '❌');
        console.log();
        
        // 10. Error Handling
        console.log('🔟 Testing Error Handling...');
        try {
            await dnca.generateEncryptionKey({ type: 'invalid' } as any);
            console.log('❌ Should throw error for invalid master key');
        } catch (error) {
            console.log('✅ Throws error for invalid master key:', (error as Error).message.substring(0, 30) + '...');
        }
        
        try {
            await dnca.encrypt(testMessage, { type: 'invalid' } as any);
            console.log('❌ Should throw error for invalid key type');
        } catch (error) {
            console.log('✅ Throws error for invalid key type:', (error as Error).message.substring(0, 30) + '...');
        }
        
        console.log('\n🎉 All DNCA3072 API features demonstrated successfully!');
        
    } catch (error) {
        console.error('❌ Error during demonstration:', error);
    }
}

// Run the demonstration
demonstrateAPI();