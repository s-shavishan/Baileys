// useEncryptedAuthState.ts
// A secure, single-file auth state replacement for Baileys
// Stores everything encrypted with AES-256
// Ready for WA-SAKURA 🫡❤️‍🔥

import { promises as fs } from 'fs'
import { join } from 'path'
import crypto from 'crypto'
import { proto } from '../../WAProto/index.js'
import type {
  AuthenticationCreds,
  AuthenticationState,
  SignalDataTypeMap
} from '../Types'
import { initAuthCreds } from './auth-utils'

// ----------------- CONFIG -----------------
const ALGORITHM = 'aes-256-gcm'
const IV_LENGTH = 16

// derive a strong 32-byte key from password
const deriveKey = (password: string) =>
  crypto.createHash('sha256').update(password).digest()

// encrypt object -> Buffer
const encrypt = (data: any, password: string): Buffer => {
  const iv = crypto.randomBytes(IV_LENGTH)
  const key = deriveKey(password)
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv)
  const json = JSON.stringify(data)
  const encrypted = Buffer.concat([cipher.update(json, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return Buffer.concat([iv, tag, encrypted])
}

// decrypt Buffer -> object
const decrypt = (buffer: Buffer, password: string): any => {
  const iv = buffer.subarray(0, IV_LENGTH)
  const tag = buffer.subarray(IV_LENGTH, IV_LENGTH + 16)
  const data = buffer.subarray(IV_LENGTH + 16)
  const key = deriveKey(password)
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv)
  decipher.setAuthTag(tag)
  const decrypted = Buffer.concat([decipher.update(data), decipher.final()])
  return JSON.parse(decrypted.toString('utf8'))
}

// ----------------- MAIN FUNCTION -----------------
export const useEncryptedAuthState = async (
  filePath: string,
  password: string
): Promise<{ state: AuthenticationState; saveCreds: () => Promise<void> }> => {
  let creds: AuthenticationCreds
  let keys: { [key: string]: { [id: string]: any } } = {}

  // try loading file
  try {
    const buffer = await fs.readFile(filePath)
    const parsed = decrypt(buffer, password)
    creds = parsed.creds
    keys = parsed.keys
  } catch {
    creds = initAuthCreds()
    keys = {}
  }

  const saveState = async () => {
    const tmpPath = filePath + '.tmp'
    const data = { creds, keys }
    const encrypted = encrypt(data, password)
    await fs.writeFile(tmpPath, encrypted)
    await fs.rename(tmpPath, filePath)
  }

  const state: AuthenticationState = {
    creds,
    keys: {
      get: async (type, ids) => {
        const data: { [_: string]: SignalDataTypeMap[typeof type] } = {}
        for (const id of ids) {
          let value = keys?.[type]?.[id]
          if (type === 'app-state-sync-key' && value) {
            value = proto.Message.AppStateSyncKeyData.fromObject(value)
          }
          data[id] = value
        }
        return data
      },
      set: async (data) => {
        for (const category in data) {
          for (const id in data[category as keyof SignalDataTypeMap]) {
            const value = data[category as keyof SignalDataTypeMap]![id]
            if (!keys[category]) keys[category] = {}
            if (value) {
              keys[category]![id] = value
            } else {
              delete keys[category]![id]
            }
          }
        }
        await saveState()
      }
    }
  }

  return { state, saveCreds: saveState }
}

// ----------------- HELPERS -----------------
// Export current auth as JSON (unencrypted)
export const exportAuth = async (filePath: string, password: string) => {
  const buffer = await fs.readFile(filePath)
  return decrypt(buffer, password)
}

// Import JSON state (unencrypted) and save encrypted
export const importAuth = async (
  filePath: string,
  password: string,
  data: any
) => {
  const buffer = encrypt(data, password)
  await fs.writeFile(filePath, buffer)
}
