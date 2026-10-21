import { createHash, timingSafeEqual } from 'node:crypto'

// Comparación en tiempo constante (evita timing attacks)
function safeEqual(a, b) {
  const ha = createHash('sha256').update(a).digest()
  const hb = createHash('sha256').update(b).digest()
  return timingSafeEqual(ha, hb)
}

// ---- Límite de intentos fallidos con el secret ----
// En memoria: se reinicia con cada arranque en frío y no se comparte entre instancias
// (ni entre funciones), así que frena la fuerza bruta "casual", no es una barrera absoluta.
const MAX_FAILS = 5
const WINDOW_MS = 15 * 60 * 1000
const fails = new Map() // ip -> { count, resetAt }

function clientIp(req) {
  const xff = req.headers['x-forwarded-for']
  const first = typeof xff === 'string' ? xff.split(',')[0].trim() : ''
  return first || req.socket?.remoteAddress || 'unknown'
}

function currentEntry(ip, now) {
  const entry = fails.get(ip)
  if (!entry) return null
  if (entry.resetAt <= now) {
    fails.delete(ip)
    return null
  }
  return entry
}

function registerFail(ip, now) {
  if (fails.size > 1000) {
    for (const [key, value] of fails) if (value.resetAt <= now) fails.delete(key)
  }
  const entry = currentEntry(ip, now)
  if (entry) entry.count++
  else fails.set(ip, { count: 1, resetAt: now + WINDOW_MS })
}

// CORS: la web (GitHub Pages) está en otro dominio que la API
export function setCors(res, methods) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', methods)
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type')
}

// Devuelve true si el token es correcto. Si no, ya ha respondido (429/500/401) y devuelve false.
export function authorize(req, res) {
  const now = Date.now()
  const ip = clientIp(req)

  const entry = currentEntry(ip, now)
  if (entry && entry.count >= MAX_FAILS) {
    res.setHeader('Retry-After', String(Math.ceil((entry.resetAt - now) / 1000)))
    res.status(429).json({ error: 'Demasiados intentos. Inténtalo más tarde' })
    return false
  }

  const secret = process.env.API_SECRET
  if (!secret) {
    console.error('API_SECRET no está configurado')
    res.status(500).json({ error: 'Error interno' })
    return false
  }

  const auth = req.headers.authorization || ''
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : ''
  if (!token || !safeEqual(token, secret)) {
    registerFail(ip, now)
    res.status(401).json({ error: 'No autorizado' })
    return false
  }

  fails.delete(ip)
  return true
}