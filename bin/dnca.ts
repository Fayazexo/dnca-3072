#!/usr/bin/env ts-node

import { Command } from 'commander';
import chalk from 'chalk';
import { promises as fs } from 'fs';
import DNCA3072, { MasterKey, EncryptionKey, DecryptionKey, DNCAKey } from '../src/dnca';

const program = new Command();

// Helper function to serialize BigInt values to Base64
function serializeBigInt(key: string, value: any): any {
  if (typeof value === 'bigint') {
    const hex = value.toString(16).padStart(768, '0');
    const bytes = hex.match(/.{2}/g)!.map(byte => parseInt(byte, 16));
    return Buffer.from(bytes).toString('base64');
  }
  return value;
}

// Helper function to deserialize Base64 values to BigInt
function deserializeBigInt(key: string, value: any): any {
  if (key === 'private' || key === 'public' || key === 'key' || key === 'masterPublic' || key === 'encryptionKeyHash' || key === 'encryptionKey') {
    const bytes = Buffer.from(value, 'base64');
    return BigInt('0x' + bytes.toString('hex'));
  }
  return value;
}

// Helper function to save key to file
async function saveKeyToFile(filePath: string, keyObject: any): Promise<void> {
  const serialized = JSON.stringify(keyObject, serializeBigInt, 2);
  await fs.writeFile(filePath, serialized);
}

// Helper function to load key from file
async function loadKeyFromFile<T extends DNCAKey>(filePath: string): Promise<T> {
  const keyData = await fs.readFile(filePath, 'utf8');
  return JSON.parse(keyData, deserializeBigInt) as T;
}

program
  .name('dnca')
  .description('DNCA3072 - Dual-key encryption CLI tool')
  .version('1.0.0');

// Generate master key
program
  .command('keygen')
  .description('Generate a new master key pair')
  .option('-o, --output <file>', 'Output file for the master key', 'master.key')
  .action(async (options: { output: string }) => {
    try {
      const dnca = new DNCA3072();
      const masterKey = await dnca.generateMasterKey();
      
      await saveKeyToFile(options.output, masterKey);
      
      console.log(chalk.green('Master key generated successfully!'));
      console.log(chalk.blue(`Saved to: ${options.output}`));
      console.log(chalk.yellow('Keep this file secure - it contains your private key!'));
    } catch (error) {
      console.error(chalk.red('Error generating master key:'), (error as Error).message);
      process.exit(1);
    }
  });

// Generate encryption key
program
  .command('enckey')
  .description('Generate an encryption key from master key')
  .requiredOption('-m, --master <file>', 'Master key file')
  .option('-o, --output <file>', 'Output file for encryption key', 'encryption.key')
  .action(async (options: { master: string; output: string }) => {
    try {
      const dnca = new DNCA3072();
      const masterKey = await loadKeyFromFile<MasterKey>(options.master);
      
      const encryptionKey = await dnca.generateEncryptionKey(masterKey);
      
      await saveKeyToFile(options.output, encryptionKey);
      
      console.log(chalk.green('Encryption key generated successfully!'));
      console.log(chalk.blue(`Saved to: ${options.output}`));
    } catch (error) {
      console.error(chalk.red('Error generating encryption key:'), (error as Error).message);
      process.exit(1);
    }
  });

// Generate decryption key
program
  .command('deckey')
  .description('Generate a decryption key from master and encryption keys')
  .requiredOption('-m, --master <file>', 'Master key file')
  .requiredOption('-e, --encryption <file>', 'Encryption key file')
  .option('-o, --output <file>', 'Output file for decryption key', 'decryption.key')
  .action(async (options: { master: string; encryption: string; output: string }) => {
    try {
      const dnca = new DNCA3072();
      
      const masterKey = await loadKeyFromFile<MasterKey>(options.master);
      const encryptionKey = await loadKeyFromFile<EncryptionKey>(options.encryption);
      
      const decryptionKey = await dnca.generateDecryptionKey(masterKey, encryptionKey);
      
      // Special serialization for decryption key (encryptionKeyHash needs different padding)
      const serialized = JSON.stringify(decryptionKey, (key, value) => {
        if (typeof value === 'bigint') {
          const padding = key === 'encryptionKeyHash' ? 64 : 768;
          const hex = value.toString(16).padStart(padding, '0');
          const bytes = hex.match(/.{2}/g)!.map(byte => parseInt(byte, 16));
          return Buffer.from(bytes).toString('base64');
        }
        return value;
      }, 2);
      
      await fs.writeFile(options.output, serialized);
      
      console.log(chalk.green('Decryption key generated successfully!'));
      console.log(chalk.blue(`Saved to: ${options.output}`));
      console.log(chalk.cyan(`Key ID: ${decryptionKey.keyId}`));
    } catch (error) {
      console.error(chalk.red('Error generating decryption key:'), (error as Error).message);
      process.exit(1);
    }
  });

// Encrypt data
program
  .command('encrypt')
  .description('Encrypt data using master or encryption key')
  .requiredOption('-k, --key <file>', 'Key file (master or encryption key)')
  .option('-i, --input <file>', 'Input file (if not provided, reads from stdin)')
  .option('-o, --output <file>', 'Output file (if not provided, writes to stdout)')
  .action(async (options: { key: string; input?: string; output?: string }) => {
    try {
      const dnca = new DNCA3072();
      
      const key = await loadKeyFromFile<MasterKey | EncryptionKey>(options.key);
      
      let plaintext: string;
      if (options.input) {
        plaintext = await fs.readFile(options.input, 'utf8');
      } else {
        // Read from stdin
        plaintext = await new Promise<string>((resolve) => {
          let data = '';
          process.stdin.on('data', (chunk: Buffer) => data += chunk.toString());
          process.stdin.on('end', () => resolve(data));
        });
      }
      
      const encrypted = await dnca.encrypt(plaintext, key);
      
      if (options.output) {
        await fs.writeFile(options.output, encrypted);
        console.log(chalk.green('Data encrypted successfully!'));
        console.log(chalk.blue(`Saved to: ${options.output}`));
      } else {
        console.log(encrypted);
      }
    } catch (error) {
      console.error(chalk.red('Error encrypting data:'), (error as Error).message);
      process.exit(1);
    }
  });

// Decrypt data  
program
  .command('decrypt')
  .description('Decrypt data using master or decryption key')
  .requiredOption('-k, --key <file>', 'Key file (master or decryption key)')
  .option('-i, --input <file>', 'Input file (if not provided, reads from stdin)')
  .option('-o, --output <file>', 'Output file (if not provided, writes to stdout)')
  .action(async (options: { key: string; input?: string; output?: string }) => {
    try {
      const dnca = new DNCA3072();
      
      const key = await loadKeyFromFile<MasterKey | DecryptionKey>(options.key);
      
      let encryptedData: string;
      if (options.input) {
        encryptedData = await fs.readFile(options.input, 'utf8');
      } else {
        // Read from stdin
        encryptedData = await new Promise<string>((resolve) => {
          let data = '';
          process.stdin.on('data', (chunk: Buffer) => data += chunk.toString());
          process.stdin.on('end', () => resolve(data));
        });
      }
      
      let result;
      if (key.type === 'master') {
        result = await dnca.decryptWithMaster(encryptedData, key as MasterKey);
      } else if (key.type === 'decryption') {
        result = await dnca.decrypt(encryptedData, key as DecryptionKey);
      } else {
        throw new Error('Invalid key type for decryption');
      }
      
      if (options.output) {
        await fs.writeFile(options.output, result.plaintext);
        console.log(chalk.green('Data decrypted successfully!'));
        console.log(chalk.blue(`Saved to: ${options.output}`));
        console.log(chalk.cyan(`Decrypted by: ${result.trackingInfo.decryptedBy}`));
      } else {
        console.log(result.plaintext);
      }
    } catch (error) {
      console.error(chalk.red('Error decrypting data:'), (error as Error).message);
      process.exit(1);
    }
  });

program.parse();