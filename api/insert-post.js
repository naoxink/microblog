import { createClient } from '@supabase/supabase-js'
import { createHash, timingSafeEqual } from 'node:crypto'

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
)

// Comparación en tiempo constante (evita timing attacks)
function safeEqual(a, b) {
  const ha = createHash('sha256').update(a).digest()
  const hb = createHash('sha256').update(b).digest()
  return timingSafeEqual(ha, hb)
}

// ---- Límite de intentos fallidos con el secret ----
// En memoria: se reinicia con cada arranque en frío y no se comparte entre instancias,
// así que frena la fuerza bruta "casual", no es una barrera absoluta.
const MAX_FAILS = 5                 // fallos permitidos por IP...
const WINDOW_MS = 15 * 60 * 1000    // ...dentro de esta ventana
const fails = new Map()             // ip -> { count, resetAt }

function clientIp(req) {
  const xff = req.headers['x-forwarded-for']
  const first = typeof xff === 'string' ? xff.split(',')[0].trim() : ''
  return first || req.socket?.remoteAddress || 'unknown'
}

// Devuelve el registro vigente de la IP (y descarta el caducado)
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
  // Limpieza ocasional para que el mapa no crezca sin límite
  if (fails.size > 1000) {
    for (const [key, value] of fails) if (value.resetAt <= now) fails.delete(key)
  }
  const entry = currentEntry(ip, now)
  if (entry) entry.count++
  else fails.set(ip, { count: 1, resetAt: now + WINDOW_MS })
}

export default async function handler(req, res) {
  // CORS: la web (GitHub Pages) está en otro dominio que la API
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type')
  if (req.method === 'OPTIONS') return res.status(204).end()

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({ error: 'Método no permitido' })
  }

  const now = Date.now()
  const ip = clientIp(req)

  // Bloqueo si ya se agotaron los intentos (antes de mirar el token)
  const entry = currentEntry(ip, now)
  if (entry && entry.count >= MAX_FAILS) {
    res.setHeader('Retry-After', String(Math.ceil((entry.resetAt - now) / 1000)))
    return res.status(429).json({ error: 'Demasiados intentos. Inténtalo más tarde' })
  }

  // Configuración: si falta el secret es un error del servidor, no del cliente
  const secret = process.env.API_SECRET
  if (!secret) {
    console.error('API_SECRET no está configurado')
    return res.status(500).json({ error: 'Error interno' })
  }

  // Autenticación: Authorization: Bearer <API_SECRET>
  const auth = req.headers.authorization || ''
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : ''
  if (!token || !safeEqual(token, secret)) {
    registerFail(ip, now)
    return res.status(401).json({ error: 'No autorizado' })
  }

  // Autenticación correcta: se borran los fallos previos de esta IP
  fails.delete(ip)

  // Validación del body
  let body = req.body
  if (typeof body === 'string') {
    try { body = JSON.parse(body) } catch { body = null }
  }
  const content = typeof body?.content === 'string' ? body.content.trim() : ''
  if (!content || content.length > 5000) {
    return res.status(400).json({ error: 'El campo "content" es obligatorio (máx. 5000 caracteres)' })
  }

  const { data, error } = await supabase
    .from('posts')
    .insert({ content })
    .select()
    .single()

  if (error) {
    console.error('Error al insertar:', error)
    return res.status(500).json({ error: 'Error interno' })
  }

  return res.status(201).json(data)
}