import DNCA3072, { MasterKey, EncryptionKey, DecryptionKey } from '../src/dnca';

async function runIntegrationTests(): Promise<boolean> {
    console.log('Running DNCA3072 Integration Tests...\n');
    
    const dnca = new DNCA3072();
    let passed = 0;
    let total = 0;
    
    function test(name: string, condition: boolean): void {
        total++;
        if (condition) {
            console.log(`✅ ${name}`);
            passed++;
        } else {
            console.log(`❌ ${name}`);
        }
    }
    
    try {
        // Test 1: Basic workflow
        const masterKey: MasterKey = await dnca.generateMasterKey();
        const encryptionKey: EncryptionKey = await dnca.generateEncryptionKey(masterKey);
        const decryptionKey: DecryptionKey = await dnca.generateDecryptionKey(masterKey, encryptionKey);
        
        const testMessage = "Integration test message with special chars: 你好世界! 🔐";
        
        // Test encryption/decryption flow
        const encrypted: string = await dnca.encrypt(testMessage, encryptionKey);
        const decrypted = await dnca.decrypt(encrypted, decryptionKey);
        
        test('Basic encryption/decryption workflow', decrypted.plaintext === testMessage);
        test('Decryption tracking info present', !!decrypted.trackingInfo && !!decrypted.trackingInfo.decryptedBy);
        
        // Test master key decryption
        const masterDecrypted = await dnca.decryptWithMaster(encrypted, masterKey);
        test('Master key can decrypt encryption-key data', masterDecrypted.plaintext === testMessage);
        
        // Test Base64 encoding output
        const encryptedData = JSON.parse(encrypted);
        test('Ciphertext uses Base64 encoding', /^[A-Za-z0-9+/]+=*$/.test(encryptedData.ciphertext));
        test('IV uses Base64 encoding', /^[A-Za-z0-9+/]+=*$/.test(encryptedData.iv));
        test('Nonce uses Base64 encoding', /^[A-Za-z0-9+/]+=*$/.test(encryptedData.nonce));
        
        // Test error conditions
        try {
            await dnca.decrypt(encrypted.replace('A', 'B'), decryptionKey);
            test('Tampered data detection', false);
        } catch (error) {
            test('Tampered data detection', (error as Error).message.includes('Authentication failed'));
        }
        
        // Test cross-key isolation
        const otherMaster: MasterKey = await dnca.generateMasterKey();
        const otherEncKey: EncryptionKey = await dnca.generateEncryptionKey(otherMaster);
        const otherDecKey: DecryptionKey = await dnca.generateDecryptionKey(otherMaster, otherEncKey);
        
        try {
            await dnca.decrypt(encrypted, otherDecKey);
            test('Cross-key isolation', false);
        } catch (error) {
            test('Cross-key isolation', true);
        }
        
        console.log(`\nIntegration Tests: ${passed}/${total} passed`);
        return passed === total;
        
    } catch (error) {
        console.error('Integration test failed:', error);
        return false;
    }
}

if (require.main === module) {
    runIntegrationTests();
}

export default runIntegrationTests;