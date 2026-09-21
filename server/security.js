import { createHmac, timingSafeEqual, createHash, randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
export const hashToken = token => createHash('sha256').update(token).digest('hex');
export const newToken = () => randomBytes(32).toString('hex');
export function validateTelegram(initData, botToken, now = Date.now()) {
  if (!botToken || typeof initData !== 'string' || initData.length > 16000) throw new Error('INVALID_AUTH');
  const params = new URLSearchParams(initData);
  const keys = [...params.keys()];
  if (new Set(keys).size !== keys.length) throw new Error('INVALID_AUTH');
  const hash = params.get('hash');
  if (!hash || !/^[0-9a-f]{64}$/i.test(hash)) throw new Error('INVALID_AUTH');
  params.delete('hash');
  const data = [...params.entries()].sort(([a],[b]) => a < b ? -1 : a > b ? 1 : 0).map(([k,v]) => `${k}=${v}`).join('\n');
  const key = createHmac('sha256', 'WebAppData').update(botToken).digest();
  const expected = createHmac('sha256', key).update(data).digest();
  if (!timingSafeEqual(expected, Buffer.from(hash,'hex'))) throw new Error('INVALID_AUTH');
  const timestamp = Number(params.get('auth_date'));
  if (!Number.isSafeInteger(timestamp) || timestamp < now/1000-3600 || timestamp > now/1000+30) throw new Error('EXPIRED_AUTH');
  const user = JSON.parse(params.get('user') || 'null');
  if (!user || !Number.isSafeInteger(user.id) || user.id <= 0 || typeof user.first_name !== 'string') throw new Error('INVALID_AUTH');
  return user;
}
export function encryptCard(value, hexKey) {
  if (!/^[0-9a-f]{64}$/i.test(hexKey || '')) throw new Error('CARD_STORAGE_DISABLED');
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', Buffer.from(hexKey,'hex'),iv);
  const encrypted = Buffer.concat([cipher.update(value,'utf8'),cipher.final()]);
  return [iv,cipher.getAuthTag(),encrypted].map(b=>b.toString('hex')).join(':');
}
export function decryptCard(value, hexKey) {
  const [iv,tag,data] = value.split(':').map(v=>Buffer.from(v,'hex'));
  const cipher = createDecipheriv('aes-256-gcm',Buffer.from(hexKey,'hex'),iv); cipher.setAuthTag(tag);
  return Buffer.concat([cipher.update(data),cipher.final()]).toString('utf8');
}
export const normalizePlate = value => value.toUpperCase().replace(/[^A-Z0-9]/g,'');
export const validPlate = value => /^\d{2}(?:[A-Z]\d{3}[A-Z]{2}|\d{3}[A-Z]{3})$/.test(normalizePlate(value));
export const transitions = {queued:['accepted','cancelled'],accepted:['washing','cancelled'],washing:['ready'],ready:['completed'],completed:[],cancelled:[]};
