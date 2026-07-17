// ───────────────────────────────────────────────────────────────
//  Backend - Venta de entradas "Torneo Madre de Ciudades"
//  MercadoPago (preferencia + webhook) + generación de QR + mail.
//  Órdenes persistidas en MySQL (Sequelize).
// ───────────────────────────────────────────────────────────────

import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import { randomUUID, createHmac, timingSafeEqual, scryptSync } from 'crypto'
import { MercadoPagoConfig, Preference, Payment } from 'mercadopago'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { mkdirSync, existsSync } from 'fs'
import QRCode from 'qrcode'
import nodemailer from 'nodemailer'
import { Op } from 'sequelize'
import { sequelize, Orden, Entrada, Usuario, Visita } from './models/index.js'

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

// ───── Auth del panel (admin / control) ─────
function hashPassword(password, salt) {
  return scryptSync(String(password), salt, 64).toString('hex')
}
function verifyPassword(password, salt, hash) {
  const a = Buffer.from(hashPassword(password, salt), 'hex')
  const b = Buffer.from(hash, 'hex')
  return a.length === b.length && timingSafeEqual(a, b)
}
// Token de sesión firmado (mini-JWT con HMAC), válido 12 h
function firmarToken(payload) {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 12 * 3600 * 1000 })).toString('base64url')
  const sig = createHmac('sha256', QR_SECRET).update(body).digest('base64url').slice(0, 32)
  return `${body}.${sig}`
}
function verificarToken(token) {
  const [body, sig] = String(token || '').split('.')
  if (!body || !sig) return null
  const esperado = createHmac('sha256', QR_SECRET).update(body).digest('base64url').slice(0, 32)
  const a = Buffer.from(sig), b = Buffer.from(esperado)
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString())
    if (p.exp && Date.now() > p.exp) return null
    return p
  } catch { return null }
}
function tokenDeReq(req) {
  return verificarToken((req.headers.authorization || '').replace(/^Bearer /, ''))
}
function requireAuth(roles) {
  return (req, res, next) => {
    const p = tokenDeReq(req)
    if (!p) return res.status(401).json({ error: 'No autorizado' })
    if (roles && !roles.includes(p.rol)) return res.status(403).json({ error: 'Sin permiso' })
    req.usuario = p
    next()
  }
}

// Carpeta donde guardamos los QR generados
const QR_DIR = join(__dirname, 'qrs')
if (!existsSync(QR_DIR)) mkdirSync(QR_DIR, { recursive: true })
app.use('/qrs', express.static(QR_DIR)) // servir las imágenes de los QR (legacy, disco efímero)

// Regenerar el QR AL VUELO desde el código firmado. Robusto ante el disco efímero de
// Render (que borra los PNG en cada deploy): mientras el código sea válido, la imagen existe.
app.get('/qr', async (req, res) => {
  try {
    const codigo = String(req.query.c || '')
    if (!verificarQR(codigo)) return res.status(400).send('QR inválido')
    const png = await QRCode.toBuffer(codigo, { width: 420, margin: 1, color: { dark: '#d6006e', light: '#ffffff' } })
    res.set('Content-Type', 'image/png')
    res.set('Cache-Control', 'public, max-age=86400')
    res.send(png)
  } catch (e) {
    console.error('❌ Error generando QR al vuelo:', e?.message || e)
    res.status(500).send('Error generando QR')
  }
})

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
        // No forzamos payer.email: dejamos que MP ofrezca los métodos según el
        // usuario logueado (incluido "dinero en cuenta"), no solo tarjetas.
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
    const type = req.query.type || req.query.topic || req.body?.type
    const paymentId = req.query['data.id'] || req.query.id || req.body?.data?.id
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

// 4b) CONFIRMAR AL VOLVER DEL PAGO — verifica el pago con MP y emite las entradas.
//     Es la red de seguridad si el webhook no llegó (servicio dormido, etc.).
app.post('/api/orders/:id/confirmar', async (req, res) => {
  try {
    const orden = await Orden.findByPk(req.params.id)
    if (!orden) return res.status(404).json({ error: 'Orden no encontrada' })

    if (orden.estado !== 'pagada') {
      let pago = null
      const pid = req.body?.payment_id || req.query.payment_id
      if (pid) pago = await paymentClient.get({ id: pid }).catch(() => null)
      // Fallback: buscar el pago aprobado por external_reference (nº de orden)
      if (!pago || pago.external_reference !== orden.id || pago.status !== 'approved') {
        const r = await paymentClient.search({ options: { external_reference: orden.id } }).catch(() => null)
        const aprobado = (r?.results || []).find(p => p.status === 'approved')
        if (aprobado) pago = aprobado
      }
      if (pago && pago.status === 'approved' && pago.external_reference === orden.id) {
        await confirmarYEmitir(orden, pago.id)
      }
    }

    const qrs = await Entrada.findAll({ where: { orden_id: orden.id }, order: [['indice', 'ASC']] })
    res.json({
      id: orden.id, nombre: orden.nombre, email: orden.email,
      cantidad: orden.cantidad, estado: orden.estado,
      qrs: qrs.map(q => ({ url: `/qr?c=${encodeURIComponent(q.codigo)}`, codigo: q.codigo })),
    })
  } catch (e) {
    console.error('❌ Error confirmando al retorno:', e?.message || e)
    res.status(500).json({ error: 'No se pudo verificar el pago' })
  }
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
      ordenes: encontradas.map(o => ({
        id: o.id, fecha: o.createdAt, cantidad: o.cantidad,
        qrs: o.qrs.map(q => ({ url: `/qr?c=${encodeURIComponent(q.codigo)}`, codigo: q.codigo, usado: q.usado })),
      })),
    })
  } catch (e) {
    console.error('❌ Error en mis-entradas:', e?.message || e)
    res.status(500).json({ error: 'No se pudieron obtener las entradas' })
  }
})

// 6) VALIDAR entrada en la puerta (escaneo del QR) — verifica firma + UN SOLO USO
//    Protegido con token de staff en el header X-Scan-Token.
app.post('/api/validar', rateLimit({ windowMs: 60000, max: 300 }), async (req, res) => {
  // Autoriza si trae sesión de control/admin O el token de escaneo por header
  const p = tokenDeReq(req)
  const okAuth = (p && ['control', 'admin'].includes(p.rol)) ||
                 (SCAN_TOKEN && req.headers['x-scan-token'] === SCAN_TOKEN)
  if (!okAuth) return res.status(401).json({ ok: false, error: 'No autorizado' })
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
      const usadas = await Entrada.count({ where: { orden_id: orden.id, usado: true } })
      return res.json({ ok: false, estado: 'usado', msg: `Ya ingresó (${yaUsado?.usadoEn})`, nombre: orden.nombre, cantidad: orden.cantidad, usadas })
    }
    const usadas = await Entrada.count({ where: { orden_id: orden.id, usado: true } })
    const esPrueba = orden.metodo === 'prueba'
    return res.json({ ok: true, estado: 'valido', msg: esPrueba ? 'PRUEBA · Ingreso OK' : 'Ingreso OK', nombre: orden.nombre, cantidad: orden.cantidad, usadas, prueba: esPrueba })
  } catch (e) {
    console.error('❌ Error validando:', e?.message || e)
    return res.status(500).json({ ok: false, error: 'Error al validar' })
  }
})

// ═══════════════════════════════════════════════════════════════
// 7) PANEL ADMIN — login + resumen de ventas
// ═══════════════════════════════════════════════════════════════
app.post('/api/admin/login', rateLimit({ windowMs: 60000, max: 10, msg: 'Demasiados intentos. Esperá un minuto.' }), async (req, res) => {
  try {
    const { usuario, password } = req.body || {}
    if (!usuario || !password) return res.status(400).json({ error: 'Faltan usuario y contraseña' })
    const u = await Usuario.findOne({ where: { usuario: String(usuario).trim() } })
    if (!u || !verifyPassword(password, u.salt, u.hash)) {
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' })
    }
    res.json({ token: firmarToken({ usuario: u.usuario, rol: u.rol }), rol: u.rol, usuario: u.usuario })
  } catch (e) {
    console.error('❌ Error en login:', e?.message || e)
    res.status(500).json({ error: 'Error al iniciar sesión' })
  }
})

// Resumen de ventas (solo admin): totales + tabla de compradores
// Registrar visita a la landing (público, fire-and-forget desde el front)
app.post('/api/visita', async (req, res) => {
  try {
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || null
    await Visita.create({ ip })
    res.json({ ok: true })
  } catch (e) {
    // Nunca romper la carga de la página por el contador
    res.json({ ok: false })
  }
})

app.get('/api/admin/resumen', requireAuth(['admin', 'venta']), async (req, res) => {
  try {
    // Excluye las órdenes de PRUEBA (metodo='prueba') para no ensuciar el panel.
    const ordenes = await Orden.findAll({ where: { estado: 'pagada', metodo: { [Op.notIn]: ['prueba', 'cortesia'] } }, order: [['createdAt', 'DESC']] })
    const totalEntradas  = ordenes.reduce((a, o) => a + o.cantidad, 0)
    const totalRecaudado = ordenes.reduce((a, o) => a + o.total, 0)
    const escaneadas     = await Entrada.count({
      where: { usado: true },
      include: [{ model: Orden, as: 'orden', attributes: [], required: true, where: { metodo: { [Op.notIn]: ['prueba', 'cortesia'] } } }],
    })

    // Visitas a la página
    const inicioHoy = new Date(); inicioHoy.setHours(0, 0, 0, 0)
    const totalVisitas     = await Visita.count()
    const visitantesUnicos = await Visita.count({ col: 'ip', distinct: true })
    const visitasHoy       = await Visita.count({ where: { createdAt: { [Op.gte]: inicioHoy } } })

    res.json({
      totalEntradas, totalRecaudado, cantidadOrdenes: ordenes.length, escaneadas,
      totalVisitas, visitantesUnicos, visitasHoy,
      ordenes: ordenes.map(o => ({
        id: o.id, metodo: o.metodo,
        nombre: o.nombre, email: o.email, dni: o.dni,
        cantidad: o.cantidad, total: o.total, fecha: o.createdAt,
      })),
    })
  } catch (e) {
    console.error('❌ Error en resumen:', e?.message || e)
    res.status(500).json({ error: 'Error al obtener el resumen' })
  }
})

// Generar una ENTRADA DE PRUEBA (solo admin): es un QR real y escaneable, pero la orden
// va marcada como metodo='prueba' → NO aparece en ventas/recaudación/ingresos del panel.
app.post('/api/admin/entrada-prueba', requireAuth(['admin']), async (req, res) => {
  try {
    const cant = Math.min(Math.max(parseInt(req.body?.cantidad, 10) || 1, 1), 5)
    const orderId = 'orden_' + randomUUID()
    await Orden.create({
      id: orderId, nombre: 'ENTRADA DE PRUEBA', email: 'prueba@torneo.local', dni: 'PRUEBA',
      metodo: 'prueba', cantidad: cant, subtotal: 0, cargo: 0, total: 0, estado: 'pagada',
    })
    const qrs = []
    for (let i = 1; i <= cant; i++) {
      const base = `${orderId}::${i}`
      const codigo = firmarQR(base)
      const url = `/qr?c=${encodeURIComponent(codigo)}`
      await Entrada.create({ orden_id: orderId, indice: i, codigo, base, url, usado: false })
      qrs.push({ indice: i, codigo, url })
    }
    res.json({ ok: true, ordenId: orderId, cantidad: cant, qrs })
  } catch (e) {
    console.error('❌ Error generando entrada de prueba:', e?.message || e)
    res.status(500).json({ error: 'No se pudo generar la entrada de prueba' })
  }
})

// Emitir una ENTRADA DE CORTESÍA (solo admin): QR real y escaneable ("Ingreso OK" normal),
// se envía por email, y NO cuenta como venta (metodo='cortesia', excluida del panel).
app.post('/api/admin/entrada-cortesia', requireAuth(['admin']), async (req, res) => {
  try {
    const nombre = String(req.body?.nombre || '').trim() || 'Invitación de cortesía'
    const email  = String(req.body?.email || '').trim()
    const cant   = Math.min(Math.max(parseInt(req.body?.cantidad, 10) || 1, 1), 10)
    if (!email) return res.status(400).json({ error: 'Falta el email de la invitada' })

    const orderId = 'orden_' + randomUUID()
    const orden = await Orden.create({
      id: orderId, nombre, email, dni: 'CORTESIA',
      metodo: 'cortesia', cantidad: cant, subtotal: 0, cargo: 0, total: 0, estado: 'pagada',
    })
    const qrs = []
    for (let i = 1; i <= cant; i++) {
      const base = `${orderId}::${i}`
      const codigo = firmarQR(base)
      const nombreArchivo = `${orderId}-${i}.png`
      const archivo = join(QR_DIR, nombreArchivo)
      await QRCode.toFile(archivo, codigo, { width: 420, margin: 1, color: { dark: '#d6006e', light: '#ffffff' } })
      qrs.push({ orden_id: orderId, indice: i, codigo, base, archivo, url: `/qr?c=${encodeURIComponent(codigo)}`, usado: false, usadoEn: null })
    }
    await Entrada.bulkCreate(qrs)
    await enviarMail(orden, qrs)   // mismo mail de siempre, con los QR adjuntos
    console.log(`🎫 Cortesía emitida: ${cant} entrada(s) → ${email} (${nombre})`)
    res.json({ ok: true, ordenId: orderId, cantidad: cant, email })
  } catch (e) {
    console.error('❌ Error emitiendo cortesía:', e?.message || e)
    res.status(500).json({ error: 'No se pudo emitir la cortesía' })
  }
})

// Ver los QR de una orden (admin/venta): para mostrarlos en pantalla y escanearlos en la puerta
app.get('/api/admin/orden/:id/qrs', requireAuth(['admin', 'venta']), async (req, res) => {
  try {
    const orden = await Orden.findByPk(req.params.id)
    if (!orden) return res.status(404).json({ error: 'Orden no encontrada' })
    const entradas = await Entrada.findAll({ where: { orden_id: orden.id }, order: [['indice', 'ASC']] })
    res.json({
      ok: true,
      nombre: orden.nombre, email: orden.email, dni: orden.dni, cantidad: orden.cantidad,
      qrs: entradas.map(e => ({ indice: e.indice, url: `/qr?c=${encodeURIComponent(e.codigo)}`, usado: e.usado })),
    })
  } catch (e) {
    console.error('❌ Error obteniendo QRs de la orden:', e?.message || e)
    res.status(500).json({ error: 'No se pudieron obtener los QR' })
  }
})

// VENTA MANUAL (admin/venta): entrada pagada por transferencia. Cuenta como venta real,
// aparece en el listado y se envía por email. Solo se pide nombre y email.
app.post('/api/admin/entrada-manual', requireAuth(['admin', 'venta']), async (req, res) => {
  try {
    const nombre = String(req.body?.nombre || '').trim()
    const email  = String(req.body?.email || '').trim()
    const cant   = Math.min(Math.max(parseInt(req.body?.cantidad, 10) || 1, 1), MAX_ENTRADAS)
    if (!nombre) return res.status(400).json({ error: 'Falta el nombre' })
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Email inválido' })

    const orderId  = 'orden_' + randomUUID()
    const subtotal = PRECIO_ENTRADA * cant
    const orden = await Orden.create({
      id: orderId, nombre, email, dni: String(req.body?.dni || 'MANUAL').trim(),
      metodo: 'transferencia', cantidad: cant, subtotal, cargo: 0, total: subtotal, estado: 'pagada',
    })
    const qrs = []
    for (let i = 1; i <= cant; i++) {
      const base = `${orderId}::${i}`
      const codigo = firmarQR(base)
      const nombreArchivo = `${orderId}-${i}.png`
      const archivo = join(QR_DIR, nombreArchivo)
      await QRCode.toFile(archivo, codigo, { width: 420, margin: 1, color: { dark: '#d6006e', light: '#ffffff' } })
      qrs.push({ orden_id: orderId, indice: i, codigo, base, archivo, url: `/qr?c=${encodeURIComponent(codigo)}`, usado: false, usadoEn: null })
    }
    await Entrada.bulkCreate(qrs)
    await enviarMail(orden, qrs)
    console.log(`💵 Venta manual (transferencia): ${cant} entrada(s) → ${email} (${nombre}) · $${subtotal}`)
    res.json({ ok: true, ordenId: orderId, cantidad: cant, email, total: subtotal, qrs: qrs.map(q => ({ indice: q.indice, url: q.url })) })
  } catch (e) {
    console.error('❌ Error en venta manual:', e?.message || e)
    res.status(500).json({ error: 'No se pudo generar la venta manual' })
  }
})

app.get('/health', (_req, res) => res.send('Backend Torneo Madre de Ciudades ✅'))

// Levantar el server YA, sin bloquear por la base (Render necesita que responda rápido)
app.listen(PORT, () => {
  console.log(`🚀 Backend corriendo en el puerto ${PORT}`)
  if (!process.env.MP_ACCESS_TOKEN) console.warn('⚠️ Falta MP_ACCESS_TOKEN')
  console.log(`💳 Pagos: MercadoPago · cargo por servicio ${CARGO_PCT}%`)
})

// Conectar a la base en segundo plano y crear las tablas (si no existen)
sequelize.authenticate()
  .then(() => sequelize.sync())
  .then(() => console.log('🗄️  Base MySQL conectada'))
  .catch(e => {
    console.error('❌ No se pudo conectar a la base:', e?.message || e)
    console.error('   Revisá DB_HOST/DB_PORT/DB_USER/DB_PASSWORD/DB_NAME y el ALLOWLIST de IPs de Aiven')
  })

// Red de seguridad: que un error async no tumbe el proceso (evita el crash-loop)
process.on('unhandledRejection', e => console.error('⚠️ unhandledRejection:', e?.message || e))
process.on('uncaughtException',  e => console.error('⚠️ uncaughtException:', e?.message || e))
