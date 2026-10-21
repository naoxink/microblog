import { createClient } from '@supabase/supabase-js'
import { authorize, setCors } from '../lib/auth.js'

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
)

const PAGE = 1000 // Supabase devuelve como máximo 1000 filas por consulta
// en-CA formatea como YYYY-MM-DD
const dayFmt = new Intl.DateTimeFormat('en-CA', {
  timeZone: 'Europe/Madrid', year: 'numeric', month: '2-digit', day: '2-digit'
})

export default async function handler(req, res) {
  setCors(res, 'GET, OPTIONS')
  if (req.method === 'OPTIONS') return res.status(204).end()

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET')
    return res.status(405).json({ error: 'Método no permitido' })
  }

  if (!authorize(req, res)) return

  // Solo se piden las fechas, paginando, y se cuentan por día
  const counts = {}
  for (let from = 0; ; from += PAGE) {
    const { data, error } = await supabase
      .from('posts')
      .select('created_at')
      .order('created_at', { ascending: true })
      .order('id', { ascending: true }) // desempate estable para paginar
      .range(from, from + PAGE - 1)

    if (error) {
      console.error('Error al leer estadísticas:', error)
      return res.status(500).json({ error: 'Error interno' })
    }

    for (const row of data) {
      const day = dayFmt.format(new Date(row.created_at))
      counts[day] = (counts[day] || 0) + 1
    }
    if (data.length < PAGE) break
  }

  return res.status(200).json({ today: dayFmt.format(new Date()), days: counts })
}