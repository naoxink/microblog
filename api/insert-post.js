import { createClient } from '@supabase/supabase-js'
import { authorize, setCors } from '../lib/auth.js'

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
)

export default async function handler(req, res) {
  setCors(res, 'POST, OPTIONS')
  if (req.method === 'OPTIONS') return res.status(204).end()

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({ error: 'Método no permitido' })
  }

  if (!authorize(req, res)) return

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