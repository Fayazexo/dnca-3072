/**
 * DNCA3072 - Dual-key encryption algorithm with AES-GCM and 3072-bit prime modulus
 * 
 * Main exports for TypeScript users
 */

// Export the default class
export { default as DNCA3072, default } from './dnca';

// Export all types
export type {
  MasterKey,
  EncryptionKey,
  DecryptionKey,
  DNCAKey,
  EncryptedData,
  DecryptionResult,
  AESResult
} from './dnca';