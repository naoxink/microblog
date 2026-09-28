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

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({ error: 'Método no permitido' })
  }

  // Autenticación: Authorization: Bearer <API_SECRET>
  const auth = req.headers.authorization || ''
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : ''
  if (!process.env.API_SECRET || !token || !safeEqual(token, process.env.API_SECRET)) {
    return res.status(401).json({ error: 'No autorizado' })
  }

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