import { Mutex } from 'async-mutex';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { mkdir, readFile, rename, stat, unlink, writeFile } from 'fs/promises';
import { dirname, join } from 'path';
import type {
  AuthenticationCreds,
  AuthenticationState,
  SignalDataTypeMap
} from '../Types'
import { initAuthCreds } from './auth-utils'
import { BufferJSON } from './generics'

const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;

interface StoredAuthState {
  creds: AuthenticationCreds;
  keys: Record<string, Record<string, any>>;
}

interface UseEncryptedAuthStateOptions {
  filePath: string;
  secret: Buffer;
  writeDelayMs?: number;
  cloudStorage?: CloudStorageAdapter;
}

interface CloudStorageAdapter {
  save(buffer: Buffer): Promise<void>;
  load(): Promise<Buffer | null>;
}

export const v2authstate = async (
  options: UseEncryptedAuthStateOptions
): Promise<{ state: AuthenticationState; saveCreds: () => Promise<void> }> => {
  const { filePath, secret, writeDelayMs = 1000, cloudStorage } = options;
  const mutex = new Mutex();
  let pendingWrite: NodeJS.Timeout | null = null;
  let storedState: StoredAuthState = {
    creds: initAuthCreds(),
    keys: {}
  };

  const ensureDirectoryExists = async (path: string): Promise<void> => {
    const dir = dirname(path);
    try {
      await stat(dir);
    } catch {
      console.log('Creating - Auth - File:', dir);
      await mkdir(dir, { recursive: true });
    }
  };

  const encrypt = (data: Buffer): Buffer => {
    console.log('Encrypting data of length:', data.length);
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, secret, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    return Buffer.concat([iv, encrypted]);
  };

  const decrypt = (data: Buffer): Buffer => {
    console.log('Decrypting data of length:', data.length);
    const iv = data.subarray(0, IV_LENGTH);
    const encrypted = data.subarray(IV_LENGTH);
    const decipher = createDecipheriv(ALGORITHM, secret, iv);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  };

  const loadState = async (): Promise<void> => {
    try {
      console.log('Loading auth state from:', filePath);
      let encryptedData: Buffer;
      
      if (cloudStorage) {
        const cloudData = await cloudStorage.load();
        if (!cloudData) return;
        encryptedData = cloudData;
      } else {
        encryptedData = await readFile(filePath);
      }

      const decrypted = decrypt(encryptedData);
      storedState = JSON.parse(decrypted.toString(), BufferJSON.reviver);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        console.error('Failed to load auth state:', error);
      }
    }
  };

  const saveState = async (): Promise<void> => {
    const release = await mutex.acquire();
    try {
      console.log('Saving auth state to:', filePath);
      const serialized = JSON.stringify(storedState, BufferJSON.replacer);
      const encrypted = encrypt(Buffer.from(serialized));

      if (cloudStorage) {
        await cloudStorage.save(encrypted);
      } else {
        await ensureDirectoryExists(filePath);
        const tempPath = `${filePath}.tmp`;

        await writeFile(tempPath, encrypted);
        await rename(tempPath, filePath);
      }
    } catch (error) {
      console.error('Failed to save auth state:', error);
      throw error;
    } finally {
      release();
    }
  };

  const scheduleSave = (): void => {
    console.log('Scheduling save in', writeDelayMs, 'ms');
    if (pendingWrite) clearTimeout(pendingWrite);
    pendingWrite = setTimeout(() => saveState(), writeDelayMs);
  };

  await loadState();

  return {
    state: {
      creds: storedState.creds,
      keys: {
        get: async (type, ids) => {
          const result: { [_: string]: SignalDataTypeMap[typeof type] } = {};
          for (const id of ids) {
            const key = `${type}-${id}`;
            result[id] = storedState.keys[key] || null;
          }
          return result;
        },
        set: async (data) => {
          for (const [category, categoryData] of Object.entries(data)) {
            for (const [id, value] of Object.entries(categoryData)) {
              const key = `${category}-${id}`;
              if (value) {
                storedState.keys[key] = value;
              } else {
                delete storedState.keys[key];
              }
            }
          }
          scheduleSave();
        }
      }
    },
    saveCreds: async () => {
      scheduleSave();
    }
  };
};

// Helper functions for backup/restore
export const exportAuthState = async (
  filePath: string,
  secret: Buffer
): Promise<StoredAuthState> => {
  const encrypted = await readFile(filePath);
  const decrypted = decrypt(encrypted);
  return JSON.parse(decrypted.toString(), BufferJSON.reviver);
};

export const importAuthState = async (
  filePath: string,
  secret: Buffer,
  state: StoredAuthState
): Promise<void> => {
  const serialized = JSON.stringify(state, BufferJSON.replacer);
  const encrypted = encrypt(Buffer.from(serialized));
  await writeFile(filePath, encrypted);
};