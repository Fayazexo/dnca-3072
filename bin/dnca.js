#!/usr/bin/env node

const { Command } = require('commander');
const chalk = require('chalk');
const fs = require('fs').promises;
const path = require('path');
const DNCA3072 = require('../src/dnca');

const program = new Command();

program
  .name('dnca')
  .description('DNCA3072 - Dual-key encryption CLI tool')
  .version('1.0.0');

// Generate master key
program
  .command('keygen')
  .description('Generate a new master key pair')
  .option('-o, --output <file>', 'Output file for the master key', 'master.key')
  .action(async (options) => {
    try {
      const dnca = new DNCA3072();
      const masterKey = await dnca.generateMasterKey();
      
      await fs.writeFile(options.output, JSON.stringify(masterKey, (key, value) => {
        if (typeof value === 'bigint') {
          const hex = value.toString(16).padStart(768, '0');
          const bytes = hex.match(/.{2}/g).map(byte => parseInt(byte, 16));
          return Buffer.from(bytes).toString('base64');
        }
        return value;
      }, 2));
      
      console.log(chalk.green('Master key generated successfully!'));
      console.log(chalk.blue(`Saved to: ${options.output}`));
      console.log(chalk.yellow('Keep this file secure - it contains your private key!'));
    } catch (error) {
      console.error(chalk.red('Error generating master key:'), error.message);
      process.exit(1);
    }
  });

// Generate encryption key
program
  .command('enckey')
  .description('Generate an encryption key from master key')
  .requiredOption('-m, --master <file>', 'Master key file')
  .option('-o, --output <file>', 'Output file for encryption key', 'encryption.key')
  .action(async (options) => {
    try {
      const dnca = new DNCA3072();
      const masterKeyData = await fs.readFile(options.master, 'utf8');
      const masterKey = JSON.parse(masterKeyData, (key, value) => {
        if (key === 'private' || key === 'public') {
          const bytes = Buffer.from(value, 'base64');
          return BigInt('0x' + bytes.toString('hex'));
        }
        return value;
      });
      
      const encryptionKey = await dnca.generateEncryptionKey(masterKey);
      
      await fs.writeFile(options.output, JSON.stringify(encryptionKey, (key, value) => {
        if (typeof value === 'bigint') {
          const hex = value.toString(16).padStart(768, '0');
          const bytes = hex.match(/.{2}/g).map(byte => parseInt(byte, 16));
          return Buffer.from(bytes).toString('base64');
        }
        return value;
      }, 2));
      
      console.log(chalk.green('Encryption key generated successfully!'));
      console.log(chalk.blue(`Saved to: ${options.output}`));
    } catch (error) {
      console.error(chalk.red('Error generating encryption key:'), error.message);
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
  .action(async (options) => {
    try {
      const dnca = new DNCA3072();
      
      const masterKeyData = await fs.readFile(options.master, 'utf8');
      const masterKey = JSON.parse(masterKeyData, (key, value) => {
        if (key === 'private' || key === 'public') {
          const bytes = Buffer.from(value, 'base64');
          return BigInt('0x' + bytes.toString('hex'));
        }
        return value;
      });
      
      const encKeyData = await fs.readFile(options.encryption, 'utf8');
      const encryptionKey = JSON.parse(encKeyData, (key, value) => {
        if (key === 'key' || key === 'masterPublic') {
          const bytes = Buffer.from(value, 'base64');
          return BigInt('0x' + bytes.toString('hex'));
        }
        return value;
      });
      
      const decryptionKey = await dnca.generateDecryptionKey(masterKey, encryptionKey);
      
      await fs.writeFile(options.output, JSON.stringify(decryptionKey, (key, value) => {
        if (typeof value === 'bigint') {
          const hex = value.toString(16).padStart(64, '0');
          const bytes = hex.match(/.{2}/g).map(byte => parseInt(byte, 16));
          return Buffer.from(bytes).toString('base64');
        }
        return value;
      }, 2));
      
      console.log(chalk.green('Decryption key generated successfully!'));
      console.log(chalk.blue(`Saved to: ${options.output}`));
      console.log(chalk.cyan(`Key ID: ${decryptionKey.keyId}`));
    } catch (error) {
      console.error(chalk.red('Error generating decryption key:'), error.message);
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
  .action(async (options) => {
    try {
      const dnca = new DNCA3072();
      
      const keyData = await fs.readFile(options.key, 'utf8');
      const key = JSON.parse(keyData, (key, value) => {
        if (key === 'private' || key === 'public' || key === 'key' || key === 'masterPublic') {
          const bytes = Buffer.from(value, 'base64');
          return BigInt('0x' + bytes.toString('hex'));
        }
        return value;
      });
      
      let plaintext;
      if (options.input) {
        plaintext = await fs.readFile(options.input, 'utf8');
      } else {
        // Read from stdin
        plaintext = await new Promise((resolve) => {
          let data = '';
          process.stdin.on('data', chunk => data += chunk);
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
      console.error(chalk.red('Error encrypting data:'), error.message);
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
  .action(async (options) => {
    try {
      const dnca = new DNCA3072();
      
      const keyData = await fs.readFile(options.key, 'utf8');
      const key = JSON.parse(keyData, (key, value) => {
        if (key === 'private' || key === 'public' || key === 'key' || key === 'masterPublic' || key === 'encryptionKeyHash') {
          const bytes = Buffer.from(value, 'base64');
          return BigInt('0x' + bytes.toString('hex'));
        }
        return value;
      });
      
      let encryptedData;
      if (options.input) {
        encryptedData = await fs.readFile(options.input, 'utf8');
      } else {
        // Read from stdin
        encryptedData = await new Promise((resolve) => {
          let data = '';
          process.stdin.on('data', chunk => data += chunk);
          process.stdin.on('end', () => resolve(data));
        });
      }
      
      let result;
      if (key.type === 'master') {
        result = await dnca.decryptWithMaster(encryptedData, key);
      } else if (key.type === 'decryption') {
        result = await dnca.decrypt(encryptedData, key);
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
      console.error(chalk.red('Error decrypting data:'), error.message);
      process.exit(1);
    }
  });

program.parse();