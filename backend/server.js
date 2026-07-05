// ───────────────────────────────────────────────────────────────
//  Backend - Venta de entradas "Torneo Madre de Ciudades"
//  MercadoPago (preferencia + webhook) + generación de QR + mail.
//  Órdenes persistidas en MySQL (Sequelize).
// ───────────────────────────────────────────────────────────────

import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import { randomUUID, createHmac, timingSafeEqual } from 'crypto'
import { MercadoPagoConfig, Preference, Payment } from 'mercadopago'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { mkdirSync, existsSync } from 'fs'
import QRCode from 'qrcode'
import nodemailer from 'nodemailer'
import { sequelize, Orden, Entrada } from './models/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
dotenv.config({ path: join(__dirname, '.env') })

const app = express()
app.use(cors())
app.use(express.json())

// Servir el frontend (el landing) desde ../frontend  ->  http://localhost:PORT/
app.use(express.static(join(__dirname, '..', 'frontend')))

// ───── Configuración ─────
const PORT = process.env.PORT || 3010
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5500'
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`
const PRECIO_ENTRADA = Number(process.env.PRECIO_ENTRADA) || 10000
const CARGO_PCT = Number(process.env.CARGO_PCT) || 12 // % de cargo por servicio (lo paga el comprador)
const MAX_ENTRADAS = Number(process.env.MAX_ENTRADAS) || 20
const IS_PROD = process.env.NODE_ENV === 'production'
const QR_SECRET = process.env.QR_SECRET || 'CAMBIAR_ESTE_SECRETO_EN_PRODUCCION'
const SCAN_TOKEN = process.env.SCAN_TOKEN || '' // token para el escaneo en puerta (staff)

// ───── Seguridad ─────
// Firma HMAC del contenido del QR → no se puede falsificar sin el secreto.
function firmarQR(base) {
  const sig = createHmac('sha256', QR_SECRET).update(base).digest('hex').slice(0, 16)
  return `${base}::${sig}`
}
function verificarQR(codigo) {
  const parts = String(codigo).split('::')
  if (parts.length < 3) return null
  const sig  = parts.pop()
  const base = parts.join('::')
  const esperado = createHmac('sha256', QR_SECRET).update(base).digest('hex').slice(0, 16)
  const a = Buffer.from(sig), b = Buffer.from(esperado)
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null
  return base // "orderId::index"
}
// Escapa HTML (para no inyectar en el mail)
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]))
}
// Rate limiting simple en memoria, por IP
function rateLimit({ windowMs, max, msg }) {
  const hits = new Map()
  return (req, res, next) => {
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'x'
    const now = Date.now()
    let rec = hits.get(ip)
    if (!rec || now > rec.reset) { rec = { count: 0, reset: now + windowMs }; hits.set(ip, rec) }
    rec.count++
    if (rec.count > max) return res.status(429).json({ error: msg || 'Demasiadas solicitudes. Probá en un momento.' })
    next()
  }
}

// Carpeta donde guardamos los QR generados
const QR_DIR = join(__dirname, 'qrs')
if (!existsSync(QR_DIR)) mkdirSync(QR_DIR, { recursive: true })
app.use('/qrs', express.static(QR_DIR)) // servir las imágenes de los QR

// ───── MercadoPago ─────
const mp = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN })
const preferenceClient = new Preference(mp)
const paymentClient = new Payment(mp)

// ═══════════════════════════════════════════════════════════════
//  EMAIL (demo con Ethereal: genera un link para VER el mail enviado)
// ═══════════════════════════════════════════════════════════════
let _transporter = null
async function getTransporter() {
  if (_transporter) return _transporter
  // Si hay credenciales de Gmail en el .env → envío REAL a la bandeja
  if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    _transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
      tls: { rejectUnauthorized: false }, // evita "self-signed certificate" (antivirus/proxy local)
    })
    console.log(`📮 Email: Gmail (${process.env.EMAIL_USER})`)
  } else {
    // Fallback: Ethereal (solo preview, no llega a una bandeja real)
    const testAcc = await nodemailer.createTestAccount()
    _transporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email', port: 587, secure: false,
      auth: { user: testAcc.user, pass: testAcc.pass },
    })
    console.log('📮 Email: Ethereal (preview)')
  }
  return _transporter
}

async function enviarMail(orden, qrs) {
  const t = await getTransporter()
  const attachments = qrs.map((q, i) => ({
    filename: `entrada-${i + 1}.png`, path: q.archivo, cid: `qr${i}`,
  }))
  const htmlQrs = qrs.map((q, i) => `
    <div style="text-align:center;margin:18px;padding:16px;border:1px solid #f3d6e6;border-radius:12px;">
      <p style="color:#d6006e;font-weight:700;">Entrada ${i + 1} de ${orden.cantidad}</p>
      <img src="cid:qr${i}" width="220" alt="QR">
      <p style="font-size:11px;color:#999;">${q.codigo}</p>
    </div>`).join('')

  const info = await t.sendMail({
    from: `"Torneo Madre de Ciudades" <${process.env.EMAIL_USER || 'entradas@santiagoritmica.com'}>`,
    to: orden.email,
    subject: `🎟️ Tus ${orden.cantidad} entrada(s) — Torneo Madre de Ciudades`,
    html: `
      <div style="font-family:Segoe UI,Arial,sans-serif;max-width:560px;margin:auto;">
        <h2 style="color:#d6006e;">¡Gracias por tu compra, ${escapeHtml(orden.nombre)}! 🎀</h2>
        <p>Estas son tus entradas para el <b>Torneo Madre de Ciudades</b> (Sáb 18 de Julio · Estadio Quimsa).
        Mostrá el QR en la puerta desde tu celular o impreso.</p>
        ${htmlQrs}
        <p style="font-size:12px;color:#999;">Orden ${orden.id}</p>
      </div>`,
    attachments,
  })
  orden.emailPreview = nodemailer.getTestMessageUrl(info) || null
  if (orden.emailPreview) console.log(`📧 Mail (preview): ${orden.emailPreview}`)
  else console.log(`📧 Mail enviado a ${orden.email} — revisá tu bandeja (y spam)`)
}

// ═══════════════════════════════════════════════════════════════
//  CONFIRMAR ORDEN + EMITIR QR  (lo usan el webhook Y la simulación)
// ═══════════════════════════════════════════════════════════════
async function confirmarYEmitir(orden, paymentId = null) {
  // Idempotencia ATÓMICA: solo el primero que la pasa a "pagada" emite las entradas
  // (evita emitir dos veces si llegan dos webhooks juntos).
  const campos = { estado: 'pagada' }
  if (paymentId) campos.paymentId = paymentId
  const [afectadas] = await Orden.update(campos, { where: { id: orden.id, estado: 'pendiente' } })
  if (!afectadas) return // ya estaba pagada
  orden.estado = 'pagada'
  if (paymentId) orden.paymentId = paymentId

  // Un QR por entrada
  const qrs = []
  for (let i = 1; i <= orden.cantidad; i++) {
    const base   = `${orden.id}::${i}`
    const codigo = firmarQR(base) // QR firmado (HMAC) → no se puede falsificar
    const nombreArchivo = `${orden.id}-${i}.png`
    const archivo = join(QR_DIR, nombreArchivo)
    await QRCode.toFile(archivo, codigo, {
      width: 420, margin: 1, color: { dark: '#d6006e', light: '#ffffff' },
    })
    qrs.push({ orden_id: orden.id, indice: i, codigo, base, archivo, url: `/qrs/${nombreArchivo}`, usado: false, usadoEn: null })
  }
  await Entrada.bulkCreate(qrs)

  await enviarMail(orden, qrs)
  console.log(`✅ Orden ${orden.id} PAGADA → ${qrs.length} QR generados + mail a ${orden.email}`)
}

// ═══════════════════════════════════════════════════════════════
// 1) CREAR ORDEN + PREFERENCIA DE PAGO
// ═══════════════════════════════════════════════════════════════
app.post('/api/orders', rateLimit({ windowMs: 60000, max: 15 }), async (req, res) => {
  try {
    const { nombre, email, dni, cantidad = 1, metodo = 'mp' } = req.body
    if (!nombre || !email || !dni) {
      return res.status(400).json({ error: 'Faltan datos (nombre, email, dni)' })
    }

    const cant = parseInt(cantidad, 10)
    if (!Number.isInteger(cant) || cant < 1 || cant > MAX_ENTRADAS) {
      return res.status(400).json({ error: `Cantidad inválida (permitido: 1 a ${MAX_ENTRADAS})` })
    }

    const orderId = 'orden_' + randomUUID()
    const subtotal = PRECIO_ENTRADA * cant
    const cargo = Math.round(subtotal * CARGO_PCT / 100)
    const total = subtotal + cargo

    await Orden.create({
      id: orderId, nombre, email, dni, metodo,
      cantidad: cant, subtotal, cargo, total,
      estado: 'pendiente',
    })

    // ─── PAGO POR MERCADOPAGO (tarjeta / débito / dinero en cuenta) ───
    const items = [{
      title: 'Entrada · Torneo Madre de Ciudades',
      quantity: cant, unit_price: PRECIO_ENTRADA, currency_id: 'ARS',
    }]
    if (cargo > 0) items.push({
      title: 'Cargo por servicio', quantity: 1, unit_price: cargo, currency_id: 'ARS',
    })

    const pref = await preferenceClient.create({
      body: {
        items,
        external_reference: orderId,
        payer: { name: nombre, email },
        back_urls: {
          success: `${FRONTEND_URL}/pago-exitoso.html?orden=${orderId}`,
          pending: `${FRONTEND_URL}/pago-pendiente.html?orden=${orderId}`,
          failure: `${FRONTEND_URL}/pago-fallido.html?orden=${orderId}`,
        },
        auto_return: 'approved', // redirige solo al sitio cuando el pago se aprueba
        notification_url: `${PUBLIC_URL}/api/webhooks/mp`,
        // payment_methods: { excluded_payment_types: [{ id: 'credit_card' }] },
      },
    })

    console.log(`🧾 Orden creada: ${orderId} ($${total})`)
    res.json({ orderId, init_point: pref.init_point })
  } catch (e) {
    console.error('❌ Error creando orden:', e?.message || e)
    res.status(500).json({ error: 'No se pudo crear la orden' })
  }
})

// ═══════════════════════════════════════════════════════════════
// 2) WEBHOOK de MercadoPago → confirma el pago y emite el QR
// ═══════════════════════════════════════════════════════════════
app.post('/api/webhooks/mp', async (req, res) => {
  res.sendStatus(200) // responder rápido siempre
  try {
    const type = req.query.type || req.body?.type
    const paymentId = req.query['data.id'] || req.body?.data?.id
    if (type !== 'payment' || !paymentId) return

    const pago = await paymentClient.get({ id: paymentId })
    const orden = await Orden.findByPk(pago.external_reference)
    if (!orden) return console.log(`⚠️ Webhook: orden ${pago.external_reference} no encontrada`)

    if (pago.status === 'approved') {
      const net = pago.transaction_details?.net_received_amount
      const fees = (pago.fee_details || []).map(f => `${f.type} $${f.amount}`).join(' | ')
      console.log(`💰 Pago aprobado | método: ${pago.payment_type_id}/${pago.payment_method_id} | total $${pago.transaction_amount} | NETO recibido $${net} | comisiones: ${fees || '—'}`)
      await confirmarYEmitir(orden, paymentId)
    } else {
      console.log(`ℹ️ Orden ${orden.id}: pago "${pago.status}"`)
    }
  } catch (e) {
    console.error('❌ Error en webhook:', e?.message || e)
  }
})

// ═══════════════════════════════════════════════════════════════
// 3) DEV: simular el pago de una orden (mismo flujo que el webhook)
//     ⚠️ SOLO para pruebas locales. Quitar en producción.
// ═══════════════════════════════════════════════════════════════
app.post('/api/dev/confirmar/:orden', async (req, res) => {
  if (IS_PROD) return res.sendStatus(404) // 🔒 deshabilitado en producción (evita emitir entradas sin pago)
  try {
    const orden = await Orden.findByPk(req.params.orden)
    if (!orden) return res.status(404).json({ error: 'Orden no encontrada' })
    await confirmarYEmitir(orden)
    const qrs = await Entrada.findAll({ where: { orden_id: orden.id } })
    res.json({
      ok: true, estado: orden.estado,
      emailPreview: orden.emailPreview,
      qrs: qrs.map(q => q.archivo),
    })
  } catch (e) {
    console.error('❌ Error confirmando:', e?.message || e)
    res.status(500).json({ error: 'No se pudo confirmar/emitir' })
  }
})

// 4) Consultar estado de una orden
app.get('/api/orders/:id', async (req, res) => {
  const orden = await Orden.findByPk(req.params.id, { include: [{ model: Entrada, as: 'qrs' }] })
  if (!orden) return res.status(404).json({ error: 'Orden no encontrada' })
  res.json(orden)
})

// 5) "Mis Entradas": buscar entradas pagadas por email + DNI (passwordless)
app.post('/api/mis-entradas', rateLimit({ windowMs: 60000, max: 10, msg: 'Demasiados intentos. Esperá un minuto.' }), async (req, res) => {
  const { email, dni } = req.body
  if (!email || !dni) return res.status(400).json({ error: 'Faltan email y DNI' })
  const mail = String(email).trim()
  const doc = String(dni).trim()
  try {
    const encontradas = await Orden.findAll({
      where: { estado: 'pagada', email: mail, dni: doc }, // MySQL compara email sin distinguir mayúsculas
      include: [{ model: Entrada, as: 'qrs' }],
      order: [['createdAt', 'DESC']],
    })
    res.json({
      ordenes: encontradas.map(o => ({ id: o.id, fecha: o.createdAt, cantidad: o.cantidad, qrs: o.qrs })),
    })
  } catch (e) {
    console.error('❌ Error en mis-entradas:', e?.message || e)
    res.status(500).json({ error: 'No se pudieron obtener las entradas' })
  }
})

// 6) VALIDAR entrada en la puerta (escaneo del QR) — verifica firma + UN SOLO USO
//    Protegido con token de staff en el header X-Scan-Token.
app.post('/api/validar', rateLimit({ windowMs: 60000, max: 120 }), async (req, res) => {
  if (!SCAN_TOKEN || req.headers['x-scan-token'] !== SCAN_TOKEN) {
    return res.status(401).json({ ok: false, error: 'No autorizado' })
  }
  const { codigo } = req.body || {}
  if (!codigo) return res.status(400).json({ ok: false, error: 'Falta el código' })

  const base = verificarQR(codigo)
  if (!base) return res.json({ ok: false, estado: 'invalido', msg: 'QR inválido o adulterado' })

  try {
    const [orderId] = base.split('::')
    const orden = await Orden.findByPk(orderId)
    if (!orden || orden.estado !== 'pagada') {
      return res.json({ ok: false, estado: 'no_pagada', msg: 'Entrada no válida o no pagada' })
    }
    const qr = await Entrada.findOne({ where: { base } })
    if (!qr) return res.json({ ok: false, estado: 'invalido', msg: 'QR no corresponde a la orden' })

    // Marcado ATÓMICO de un solo uso: solo pasa si estaba SIN usar (evita doble escaneo)
    const [afectadas] = await Entrada.update(
      { usado: true, usadoEn: new Date() },
      { where: { base, usado: false } }
    )
    if (!afectadas) {
      const yaUsado = await Entrada.findOne({ where: { base } })
      return res.json({ ok: false, estado: 'usado', msg: `Ya ingresó (${yaUsado?.usadoEn})`, nombre: orden.nombre })
    }
    return res.json({ ok: true, estado: 'valido', msg: 'Ingreso OK', nombre: orden.nombre })
  } catch (e) {
    console.error('❌ Error validando:', e?.message || e)
    return res.status(500).json({ ok: false, error: 'Error al validar' })
  }
})

app.get('/health', (_req, res) => res.send('Backend Torneo Madre de Ciudades ✅'))

// Conectar a la base y crear las tablas (si no existen) antes de levantar el server
try {
  await sequelize.authenticate()
  await sequelize.sync() // crea 'ordenes' y 'entradas' si no existen
  console.log('🗄️  Base MySQL conectada')
} catch (e) {
  console.error('❌ No se pudo conectar a la base:', e?.message || e)
  console.error('   Revisá DB_HOST / DB_PORT / DB_USER / DB_PASSWORD / DB_NAME en el .env')
}

app.listen(PORT, () => {
  console.log(`🚀 Backend corriendo en http://localhost:${PORT}`)
  if (!process.env.MP_ACCESS_TOKEN) console.warn('⚠️ Falta MP_ACCESS_TOKEN en el .env')
  console.log(`💳 Pagos: MercadoPago · cargo por servicio ${CARGO_PCT}%`)
})
