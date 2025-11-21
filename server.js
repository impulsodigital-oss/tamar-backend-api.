// Cargar variables de entorno
require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');

// MERCADO PAGO: Importar SDK
const { MercadoPagoConfig, Preference, Payment } = require('mercadopago');

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET;

// --- CONFIGURACIONES DE PAGOS ---

// 1. MERCADO PAGO (Argentina)
const client = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });

// 2. PAYPAL (Internacional)
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;
// Cambiar a 'https://api-m.paypal.com' para PRODUCCIÓN (cuando lancen de verdad)
// Usar 'https://api-m.sandbox.paypal.com' para PRUEBAS
const PAYPAL_API = process.env.PAYPAL_API_URL || 'https://api-m.paypal.com'; 

// CONFIGURACIÓN DE BREVO
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const LIST_ID_LEADS = 1;
const LIST_ID_ALUMNOS = 2;

// -------------------------------------------------------------------
// -- FUNCIONES AUXILIARES
// -------------------------------------------------------------------

async function syncBrevoContact(email, nombre, listId) {
    if (!BREVO_API_KEY) return;
    try {
        const response = await fetch('https://api.brevo.com/v3/contacts', {
            method: 'POST',
            headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                email: email, 
                listIds: [listId], 
                updateEnabled: true, 
                attributes: { NOMBRE: nombre } 
            })
        });
    } catch (error) { console.error('Error Brevo:', error); }
}

// Helper para obtener Token de PayPal
async function getPayPalAccessToken() {
    const auth = Buffer.from(PAYPAL_CLIENT_ID + ':' + PAYPAL_CLIENT_SECRET).toString('base64');
    const response = await fetch(`${PAYPAL_API}/v1/oauth2/token`, {
        method: 'POST',
        body: 'grant_type=client_credentials',
        headers: { Authorization: `Basic ${auth}` }
    });
    const data = await response.json();
    return data.access_token;
}

// Middlewares
app.use(express.json());
app.use(cors());

// Configuración DB
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// INICIALIZACIÓN DE BASE DE DATOS
pool.connect(async (err, client, release) => {
    if (err) { console.error('Error DB:', err.stack); return; }
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS clases_en_vivo (
                id SERIAL PRIMARY KEY,
                titulo VARCHAR(255) NOT NULL,
                profesor VARCHAR(100),
                fecha_hora TIMESTAMP NOT NULL,
                link_zoom TEXT,
                descripcion TEXT
            );
        `);
        console.log('✅ DB Inicializada.');
    } catch (tableErr) { console.error(tableErr); } 
    finally { release(); }
});

// MIDDLEWARES DE AUTH
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ error: 'Acceso denegado.' });

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido.' });
        req.userId = user.id;
        next();
    });
};

const authenticateAdmin = async (req, res, next) => {
    try {
        const result = await pool.query('SELECT email FROM usuarios WHERE id = $1', [req.userId]);
        const user = result.rows[0];
        const ADMIN_EMAIL = 'admin@tamar.com'; 
        if (user && (req.userId == 1 || user.email === ADMIN_EMAIL)) {
            next(); 
        } else {
            return res.status(403).json({ error: 'Acceso denegado.' });
        }
    } catch (error) { return res.status(500).json({ error: 'Error auth.' }); }
};

// -------------------------------------------------------------------
// -- RUTAS PÚBLICAS & AUTH (Leads, Registro, Login)
// -------------------------------------------------------------------
// (Mantengo estas rutas igual que antes, resumidas para ahorrar espacio visual)

app.post('/api/leads', async (req, res) => {
    const { nombre, email } = req.body;
    if (!nombre || !email) return res.status(400).json({ error: 'Faltan datos.' });
    try {
        const result = await pool.query('INSERT INTO usuarios (nombre, email, es_alumno_pago) VALUES ($1, $2, FALSE) ON CONFLICT (email) DO UPDATE SET nombre = EXCLUDED.nombre RETURNING id', [nombre, email]);
        await syncBrevoContact(email, nombre, LIST_ID_LEADS);
        res.status(201).json({ message: 'Lead registrado.', userId: result.rows[0].id });
    } catch (error) { res.status(500).json({ error: 'Error server.' }); }
});

app.post('/api/registro', async (req, res) => {
    const { nombre, email, password } = req.body;
    try {
        const existingUser = await pool.query('SELECT id FROM usuarios WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) return res.status(409).json({ error: 'Email registrado.' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query('INSERT INTO usuarios (nombre, email, password_hash, es_alumno_pago) VALUES ($1, $2, $3, FALSE) RETURNING id', [nombre, email, hashedPassword]);
        const nuevoUsuarioId = result.rows[0].id;
        const token = jwt.sign({ id: nuevoUsuarioId }, jwtSecret, { expiresIn: '7d' });
        await syncBrevoContact(email, nombre, LIST_ID_LEADS);
        res.status(201).json({ message: 'Cuenta creada.', userId: nuevoUsuarioId, token: token, requierePago: true });
    } catch (error) { res.status(500).json({ error: 'Error server.' }); }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT id, nombre, password_hash, es_alumno_pago FROM usuarios WHERE email = $1', [email]);
        const user = result.rows[0];
        if (!user || !await bcrypt.compare(password, user.password_hash)) return res.status(401).json({ error: 'Credenciales incorrectas.' });
        const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '7d' });
        if (user.es_alumno_pago !== true) return res.json({ message: 'Pago pendiente.', userId: user.id, nombre: user.nombre, token: token, requierePago: true });
        res.json({ message: 'Bienvenido.', userId: user.id, nombre: user.nombre, token: token, requierePago: false });
    } catch (error) { res.status(500).json({ error: 'Error server.' }); }
});

// -------------------------------------------------------------------
// -- RUTAS DE PAGOS (MERCADO PAGO Y PAYPAL)
// -------------------------------------------------------------------

// 1. MERCADO PAGO (ARS)
app.post('/api/crear-pago', authenticateToken, async (req, res) => {
    try {
        const userId = req.userId;
        const userResult = await pool.query('SELECT email, nombre FROM usuarios WHERE id = $1', [userId]);
        const user = userResult.rows[0];
        const preference = new Preference(client);
        const result = await preference.create({
            body: {
                items: [{ id: 'curso-tamar-completo', title: 'Escuela Tamar (Acceso Total)', quantity: 1, unit_price: 50000, currency_id: 'ARS' }],
                payer: { email: user.email, name: user.nombre },
                back_urls: {
                    success: 'https://tamarescuela.netlify.app/videos.html?status=success',
                    failure: 'https://tamarescuela.netlify.app/videos.html?status=failure',
                    pending: 'https://tamarescuela.netlify.app/videos.html?status=pending'
                },
                auto_return: 'approved',
                notification_url: 'https://tamar-backend-api-gqy9.onrender.com/api/webhook/mercadopago',
                metadata: { user_id: userId }
            }
        });
        res.json({ id: result.id, init_point: result.init_point });
    } catch (error) { res.status(500).json({ error: 'Error MP.' }); }
});

// Webhook Mercado Pago
app.post('/api/webhook/mercadopago', async (req, res) => {
    const topic = req.query.topic || req.query.type;
    const paymentId = req.query.id || req.query['data.id'];
    try {
        if (topic === 'payment') {
            const payment = new Payment(client);
            const paymentInfo = await payment.get({ id: paymentId });
            if (paymentInfo.status === 'approved') {
                const userId = paymentInfo.metadata.user_id;
                if (userId) {
                    const result = await pool.query('UPDATE usuarios SET es_alumno_pago = TRUE WHERE id = $1 RETURNING email, nombre', [userId]);
                    if (result.rows.length > 0) {
                        await syncBrevoContact(result.rows[0].email, result.rows[0].nombre, LIST_ID_ALUMNOS);
                        console.log(`MP: Usuario ${userId} activado.`);
                    }
                }
            }
        }
        res.status(200).send('OK');
    } catch (error) { res.sendStatus(500); }
});

// 2. PAYPAL (USD) - NUEVO
app.post('/api/crear-pago-paypal', authenticateToken, async (req, res) => {
    try {
        const accessToken = await getPayPalAccessToken();
        const response = await fetch(`${PAYPAL_API}/v2/checkout/orders`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
            body: JSON.stringify({
                intent: 'CAPTURE',
                purchase_units: [{ amount: { currency_code: 'USD', value: '50.00' } }], // PRECIO EN DÓLARES
                application_context: {
                    return_url: `https://tamarescuela.netlify.app/videos.html?status=paypal_success`,
                    cancel_url: `https://tamarescuela.netlify.app/videos.html?status=failure`
                }
            })
        });
        const order = await response.json();
        res.json(order);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error creando orden PayPal' });
    }
});

// Capturar el pago de PayPal (El paso final para cobrar)
app.post('/api/capturar-pago-paypal', authenticateToken, async (req, res) => {
    const { orderID } = req.body;
    try {
        const accessToken = await getPayPalAccessToken();
        const response = await fetch(`${PAYPAL_API}/v2/checkout/orders/${orderID}/capture`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` }
        });
        const captureData = await response.json();

        if (captureData.status === 'COMPLETED') {
            // Activar usuario
            const result = await pool.query('UPDATE usuarios SET es_alumno_pago = TRUE WHERE id = $1 RETURNING email, nombre', [req.userId]);
            if (result.rows.length > 0) {
                await syncBrevoContact(result.rows[0].email, result.rows[0].nombre, LIST_ID_ALUMNOS);
                console.log(`PayPal: Usuario ${req.userId} activado.`);
            }
            res.json({ status: 'COMPLETED' });
        } else {
            res.status(400).json({ error: 'El pago no se completó.' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error capturando PayPal' });
    }
});

// -------------------------------------------------------------------
// -- RUTAS PROTEGIDAS (Videos, Progreso, Admin)
// -------------------------------------------------------------------

app.get('/api/videos', authenticateToken, async (req, res) => {
    try {
        const userCheck = await pool.query('SELECT es_alumno_pago FROM usuarios WHERE id = $1', [req.userId]);
        if (!userCheck.rows[0].es_alumno_pago) return res.status(403).json({ error: 'Requiere pago.', requierePago: true });

        const videos = await pool.query('SELECT * FROM videos ORDER BY modulo, orden ASC');
        const progreso = await pool.query('SELECT video_id FROM progreso_alumnos WHERE usuario_id = $1', [req.userId]);
        const completed = new Set(progreso.rows.map(r => r.video_id));
        const videosWithStatus = videos.rows.map(v => ({ ...v, completado: completed.has(v.id) }));
        
        res.json({ videos: videosWithStatus });
    } catch (e) { res.status(500).json({ error: 'Error servidor' }); }
});

app.post('/api/progreso', authenticateToken, async (req, res) => {
    try {
        await pool.query('INSERT INTO progreso_alumnos (usuario_id, video_id, fecha_completado) VALUES ($1, $2, NOW())', [req.userId, req.body.videoId]);
        res.status(201).json({ message: 'OK' });
    } catch (e) { res.status(e.code === '23505' ? 409 : 500).json({ error: 'Error' }); }
});

app.get('/api/clases-en-vivo', authenticateToken, async (req, res) => {
    try {
        const userCheck = await pool.query('SELECT es_alumno_pago FROM usuarios WHERE id = $1', [req.userId]);
        if (!userCheck.rows[0].es_alumno_pago) return res.status(403).json({ error: 'Pago requerido.' });
        const result = await pool.query('SELECT * FROM clases_en_vivo ORDER BY fecha_hora ASC');
        res.json({ clases: result.rows });
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

// ADMIN RUTAS
app.get('/api/admin/usuarios-activos', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, nombre, email FROM usuarios WHERE es_alumno_pago = TRUE ORDER BY id DESC');
        res.json({ alumnos: result.rows });
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/admin/leads-pendientes', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, nombre, email, fecha_registro FROM usuarios WHERE es_alumno_pago = FALSE ORDER BY id DESC');
        res.json({ leads: result.rows });
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

app.listen(port, () => { console.log(`Servidor en puerto ${port}`); });
