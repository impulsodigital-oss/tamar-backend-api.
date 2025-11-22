// Cargar variables de entorno
require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const { MercadoPagoConfig, Preference, Payment } = require('mercadopago');

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET;

// --- CONFIGURACIONES DE PAGOS ---
const client = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;
const PAYPAL_API = process.env.PAYPAL_API_URL || 'https://api-m.paypal.com'; 

// CONFIGURACIÓN DE BREVO
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const LIST_ID_LEADS = 1;
const LIST_ID_ALUMNOS = 2;

// --- DICCIONARIO DE PLANES (Precios) ---
const PLANES = {
    'basico': { titulo: 'Plan Básico (Mensual)', precio_usd: 39.00, precio_ars: 46800 },
    'core': { titulo: 'Plan Core (3 Clases/mes)', precio_usd: 59.00, precio_ars: 70800 },
    'plus': { titulo: 'Plan Plus (10 Clases/mes)', precio_usd: 129.00, precio_ars: 154800 },
    'selecto': { titulo: 'Plan Selecto (4 Clases/sem)', precio_usd: 109.00, precio_ars: 130800 },
    'completo': { titulo: 'Plan Completo (Full)', precio_usd: 229.00, precio_ars: 274800 },
    'certificacion': { titulo: 'Matrícula Anual Certificación', precio_usd: 200.00, precio_ars: 240000 }
};

// -------------------------------------------------------------------
// -- FUNCIONES AUXILIARES
// -------------------------------------------------------------------

async function syncBrevoContact(email, nombre, listId) {
    if (!BREVO_API_KEY) return;
    try {
        await fetch('https://api.brevo.com/v3/contacts', {
            method: 'POST', headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, listIds: [listId], updateEnabled: true, attributes: { NOMBRE: nombre } })
        });
    } catch (error) { console.error('Error Brevo:', error); }
}

async function getPayPalAccessToken() {
    if(!PAYPAL_CLIENT_ID) return null;
    const auth = Buffer.from(PAYPAL_CLIENT_ID + ':' + PAYPAL_CLIENT_SECRET).toString('base64');
    const response = await fetch(`${PAYPAL_API}/v1/oauth2/token`, { method: 'POST', body: 'grant_type=client_credentials', headers: { Authorization: `Basic ${auth}` } });
    const data = await response.json();
    return data.access_token;
}

// Middlewares
app.use(express.json());
app.use(cors());

// Configuración DB
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// INICIALIZACIÓN DB
pool.connect(async (err, client, release) => {
    if (err) return console.error('Error DB', err);
    try {
        await client.query(`CREATE TABLE IF NOT EXISTS videos (id SERIAL PRIMARY KEY, titulo_completo VARCHAR(255), titulo_corto VARCHAR(100), modulo INT, orden INT, url_video TEXT, descripcion TEXT);`);
        await client.query(`CREATE TABLE IF NOT EXISTS clases_en_vivo (id SERIAL PRIMARY KEY, titulo VARCHAR(255), materia VARCHAR(100), profesor VARCHAR(100), fecha_hora TIMESTAMP, link_zoom TEXT, link_recursos TEXT, descripcion TEXT);`);
        await client.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS plan_adquirido VARCHAR(100);`);
        console.log('✅ DB Inicializada y Actualizada.');
    } catch (e) { console.error(e); } finally { release(); }
});

// MIDDLEWARES DE AUTH
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acceso denegado' });
    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.userId = user.id; next();
    });
};

const authenticateAdmin = async (req, res, next) => {
    const result = await pool.query('SELECT email FROM usuarios WHERE id = $1', [req.userId]);
    const user = result.rows[0];
    if (user && (req.userId == 1 || user.email === 'admin@tamar.com')) next();
    else res.status(403).json({ error: 'Acceso denegado' });
};

// --- RUTAS DE AUTH ---
app.post('/api/leads', async (req, res) => {
    const { nombre, email } = req.body;
    const result = await pool.query('INSERT INTO usuarios (nombre, email, es_alumno_pago) VALUES ($1, $2, FALSE) ON CONFLICT (email) DO UPDATE SET nombre = EXCLUDED.nombre RETURNING id', [nombre, email]);
    await syncBrevoContact(email, nombre, LIST_ID_LEADS);
    res.status(201).json({ message: 'Lead registrado', userId: result.rows[0].id });
});

app.post('/api/registro', async (req, res) => {
    const { nombre, email, password } = req.body;
    try {
        const hashed = await bcrypt.hash(password, 10);
        const result = await pool.query('INSERT INTO usuarios (nombre, email, password_hash, es_alumno_pago) VALUES ($1, $2, $3, FALSE) RETURNING id', [nombre, email, hashed]);
        const token = jwt.sign({ id: result.rows[0].id }, jwtSecret, { expiresIn: '7d' });
        await syncBrevoContact(email, nombre, LIST_ID_LEADS);
        res.status(201).json({ message: 'Cuenta creada', userId: result.rows[0].id, token, requierePago: true });
    } catch (e) { res.status(500).json({ error: 'Error registro' }); }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const result = await pool.query('SELECT id, nombre, password_hash, es_alumno_pago, email FROM usuarios WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !await bcrypt.compare(password, user.password_hash)) return res.status(401).json({ error: 'Credenciales incorrectas' });
    
    const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '7d' });
    const isVIP = (user.email === 'admin@tamar.com' || user.id == 1);
    
    if (user.es_alumno_pago !== true && !isVIP) return res.json({ message: 'Pago pendiente', userId: user.id, nombre: user.nombre, token, requierePago: true });
    res.json({ message: 'Bienvenido', userId: user.id, nombre: user.nombre, token, requierePago: false });
});

// --- PAGOS ---
app.post('/api/crear-pago', authenticateToken, async (req, res) => {
    const { planId } = req.body; 
    const plan = PLANES[planId] || PLANES['basico'];
    const userId = req.userId;
    const user = (await pool.query('SELECT email, nombre FROM usuarios WHERE id = $1', [userId])).rows[0];

    try {
        const preference = new Preference(client);
        const result = await preference.create({
            body: {
                items: [{ id: planId, title: `Tamar - ${plan.titulo}`, quantity: 1, unit_price: plan.precio_ars, currency_id: 'ARS' }],
                payer: { email: user.email, name: user.nombre },
                back_urls: { success: 'https://tamarescuela.netlify.app/videos.html?status=success', failure: 'https://tamarescuela.netlify.app/videos.html?status=failure', pending: 'https://tamarescuela.netlify.app/videos.html?status=pending' },
                auto_return: 'approved',
                notification_url: 'https://tamar-backend-api-gqy9.onrender.com/api/webhook/mercadopago',
                metadata: { user_id: userId, plan_id: planId } 
            }
        });
        res.json({ id: result.id, init_point: result.init_point });
    } catch (e) { res.status(500).json({ error: 'Error MP' }); }
});

app.post('/api/webhook/mercadopago', async (req, res) => {
    const paymentId = req.query.id || req.query['data.id'];
    const topic = req.query.topic || req.query.type;
    try {
        if (topic === 'payment') {
            const payment = new Payment(client);
            const info = await payment.get({ id: paymentId });
            if (info.status === 'approved') {
                const { user_id, plan_id } = info.metadata;
                if (user_id) {
                    const planNombre = PLANES[plan_id]?.titulo || 'Plan Desconocido';
                    const result = await pool.query('UPDATE usuarios SET es_alumno_pago = TRUE, plan_adquirido = $2 WHERE id = $1 RETURNING email, nombre', [user_id, planNombre]);
                    if (result.rows.length > 0) await syncBrevoContact(result.rows[0].email, result.rows[0].nombre, LIST_ID_ALUMNOS);
                }
            }
        }
        res.status(200).send('OK');
    } catch (e) { res.sendStatus(500); }
});

app.post('/api/crear-pago-paypal', authenticateToken, async (req, res) => {
    const { planId } = req.body;
    const plan = PLANES[planId] || PLANES['basico'];
    const accessToken = await getPayPalAccessToken();
    const response = await fetch(`${PAYPAL_API}/v2/checkout/orders`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
        body: JSON.stringify({
            intent: 'CAPTURE',
            purchase_units: [{ amount: { currency_code: 'USD', value: plan.precio_usd.toString() }, description: plan.titulo, custom_id: planId }],
            application_context: { return_url: `https://tamarescuela.netlify.app/videos.html?status=paypal_success&plan=${planId}`, cancel_url: `https://tamarescuela.netlify.app/videos.html?status=failure` }
        })
    });
    const order = await response.json();
    res.json(order);
});

app.post('/api/capturar-pago-paypal', authenticateToken, async (req, res) => {
    const { orderID, planId } = req.body;
    const accessToken = await getPayPalAccessToken();
    const response = await fetch(`${PAYPAL_API}/v2/checkout/orders/${orderID}/capture`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` } });
    const data = await response.json();
    
    if (data.status === 'COMPLETED') {
        const planNombre = PLANES[planId]?.titulo || 'Plan Internacional';
        const result = await pool.query('UPDATE usuarios SET es_alumno_pago = TRUE, plan_adquirido = $2 WHERE id = $1 RETURNING email, nombre', [req.userId, planNombre]);
        if (result.rows.length > 0) await syncBrevoContact(result.rows[0].email, result.rows[0].nombre, LIST_ID_ALUMNOS);
        res.json({ status: 'COMPLETED' });
    } else { res.status(400).json({ error: 'Error PayPal' }); }
});

// --- RUTAS ADMIN (Dashboard y Gestión) ---

app.get('/api/admin/usuarios-activos', authenticateToken, authenticateAdmin, async (req, res) => {
    const result = await pool.query('SELECT id, nombre, email, plan_adquirido FROM usuarios WHERE es_alumno_pago = TRUE ORDER BY id DESC');
    res.json({ alumnos: result.rows });
});

app.get('/api/admin/leads-pendientes', authenticateToken, authenticateAdmin, async (req, res) => {
    const result = await pool.query('SELECT id, nombre, email, fecha_registro FROM usuarios WHERE es_alumno_pago = FALSE ORDER BY id DESC');
    res.json({ leads: result.rows });
});

app.post('/api/admin/activar-manual', authenticateToken, authenticateAdmin, async (req, res) => {
    const { userId, plan } = req.body;
    try {
        const result = await pool.query('UPDATE usuarios SET es_alumno_pago = TRUE, plan_adquirido = $2 WHERE id = $1 RETURNING email, nombre', [userId, plan || 'Manual/Efectivo']);
        if (result.rows.length > 0) {
            await syncBrevoContact(result.rows[0].email, result.rows[0].nombre, LIST_ID_ALUMNOS);
            res.json({ message: 'Usuario activado correctamente.' });
        } else { res.status(404).json({ error: 'Usuario no encontrado.' }); }
    } catch (error) { res.status(500).json({ error: 'Error al activar.' }); }
});

app.post('/api/admin/reset-password', authenticateToken, authenticateAdmin, async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
    const result = await pool.query('UPDATE usuarios SET password_hash = $1 WHERE email = $2 RETURNING id', [hashedPassword, req.body.email]);
    res.json({ message: result.rows.length > 0 ? 'OK' : 'User not found' });
});

app.post('/api/admin/nueva-clase', authenticateToken, authenticateAdmin, async (req, res) => {
    const { titulo, materia, profesor, fecha, hora, link_zoom, link_recursos, descripcion } = req.body;
    await pool.query(`INSERT INTO clases_en_vivo (titulo, materia, profesor, fecha_hora, link_zoom, link_recursos, descripcion) VALUES ($1, $2, $3, $4, $5, $6, $7)`, [titulo, materia, profesor, `${fecha}T${hora}:00`, link_zoom, link_recursos, descripcion]);
    res.json({ message: 'OK' });
});

// --- NUEVO: GESTIÓN DE VIDEOS (ABM) ---

// 1. Obtener videos
app.get('/api/admin/videos', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM videos ORDER BY modulo, orden ASC');
        res.json({ videos: result.rows });
    } catch (error) { res.status(500).json({ error: 'Error al obtener videos.' }); }
});

// 2. Agregar video
app.post('/api/admin/videos', authenticateToken, authenticateAdmin, async (req, res) => {
    const { titulo, corto, modulo, orden, url, desc } = req.body;
    try {
        await pool.query(
            'INSERT INTO videos (titulo_completo, titulo_corto, modulo, orden, url_video, descripcion) VALUES ($1, $2, $3, $4, $5, $6)',
            [titulo, corto, modulo, orden, url, desc]
        );
        res.json({ message: 'Video agregado exitosamente.' });
    } catch (error) { res.status(500).json({ error: 'Error al guardar video.' }); }
});

// 3. Eliminar video
app.delete('/api/admin/videos/:id', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM videos WHERE id = $1', [req.params.id]);
        res.json({ message: 'Video eliminado.' });
    } catch (error) { res.status(500).json({ error: 'Error al eliminar.' }); }
});

// --- RUTAS ALUMNO ---
app.get('/api/videos', authenticateToken, async (req, res) => {
    const user = (await pool.query('SELECT es_alumno_pago, email FROM usuarios WHERE id = $1', [req.userId])).rows[0];
    if (!user.es_alumno_pago && user.email !== 'admin@tamar.com' && req.userId != 1) return res.status(403).json({ error: 'Pago requerido', requierePago: true });
    const videos = await pool.query('SELECT * FROM videos ORDER BY modulo, orden ASC');
    const prog = await pool.query('SELECT video_id FROM progreso_alumnos WHERE usuario_id = $1', [req.userId]);
    const done = new Set(prog.rows.map(r => r.video_id));
    res.json({ videos: videos.rows.map(v => ({ ...v, completado: done.has(v.id) })) });
});

app.post('/api/progreso', authenticateToken, async (req, res) => { await pool.query('INSERT INTO progreso_alumnos (usuario_id, video_id, fecha_completado) VALUES ($1, $2, NOW())', [req.userId, req.body.videoId]); res.json({message:'OK'}); });

app.get('/api/clases-en-vivo', authenticateToken, async (req, res) => {
    const user = (await pool.query('SELECT es_alumno_pago, email FROM usuarios WHERE id = $1', [req.userId])).rows[0];
    if (!user.es_alumno_pago && user.email !== 'admin@tamar.com' && req.userId != 1) return res.status(403).json({ error: 'Pago requerido' });
    const result = await pool.query('SELECT * FROM clases_en_vivo ORDER BY fecha_hora ASC');
    res.json({ clases: result.rows });
});

// --- RUTAS SETUP ---
app.get('/api/setup/update-db-planes', async (req, res) => {
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS plan_adquirido VARCHAR(100);`);
    res.send('✅ DB Actualizada');
});
app.get('/api/setup/update-clases', async (req, res) => {
    await pool.query(`ALTER TABLE clases_en_vivo ADD COLUMN IF NOT EXISTS materia VARCHAR(100);`);
    await pool.query(`ALTER TABLE clases_en_vivo ADD COLUMN IF NOT EXISTS link_recursos TEXT;`);
    res.send('✅ DB Clases Actualizada');
});
app.get('/api/magic/activar/:email', async (req, res) => {
    try {
        const email = req.params.email;
        const result = await pool.query('UPDATE usuarios SET es_alumno_pago = TRUE WHERE email = $1 RETURNING id', [email]);
        if (result.rows.length > 0) res.send(`✅ ${email} activado.`); else res.send(`❌ ${email} no encontrado.`);
    } catch (error) { res.status(500).send('Error'); }
});

app.listen(port, () => console.log(`Server running on port ${port}`));
