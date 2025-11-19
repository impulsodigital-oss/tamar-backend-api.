// server.js

// Cargar variables de entorno
require('dotenv').config();

const express = require('express');
const { Pool } = require('pg'); 
const cors = require('cors'); 
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken'); 
const fetch = require('node-fetch'); 

// NUEVO MP: Importar SDK de Mercado Pago
const { MercadoPagoConfig, Preference, Payment } = require('mercadopago');

const app = express();
const port = process.env.PORT || 3000; 
const jwtSecret = process.env.JWT_SECRET; 

// NUEVO MP: Configuración Cliente
// Necesitas agregar MP_ACCESS_TOKEN en las variables de entorno de Render
const client = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });

// CONFIGURACIÓN DE BREVO
const BREVO_API_KEY = process.env.BREVO_API_KEY; 
const LIST_ID_LEADS = 1; 
const LIST_ID_ALUMNOS = 2; 

// ... (MANTÉN TU FUNCIÓN syncBrevoContact IGUAL QUE ANTES) ...
async function syncBrevoContact(email, nombre, listId) {
    if (!BREVO_API_KEY) return;
    try {
        const response = await fetch('https://api.brevo.com/v3/contacts', {
            method: 'POST',
            headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, listIds: [listId], updateEnabled: true, attributes: { NOMBRE: nombre } })
        });
    } catch (error) { console.error('Error Brevo:', error); }
}

// Middlewares
app.use(express.json()); 
app.use(cors()); 

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ... (MANTÉN TU MIDDLEWARE authenticateToken IGUAL QUE ANTES) ...
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

// RUTAS

// RUTA 1: Leads (Igual que antes)
app.post('/api/leads', async (req, res) => {
   // ... (Tu código original de leads va aquí, no cambia nada) ...
   // Si quieres ahorrar espacio en este chat, asumo que mantienes el código original
   // Solo asegúrate de que insertas con es_alumno_pago = FALSE (ya lo tenías así)
});

// RUTA 2: Registro de Alumno (CORREGIDA)
app.post('/api/registro', async (req, res) => {
    const { nombre, email, password } = req.body;
    if (!nombre || !email || !password) return res.status(400).json({ error: 'Datos incompletos.' });

    try {
        const existingUser = await pool.query('SELECT id FROM usuarios WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) return res.status(409).json({ error: 'Email registrado.' });

        const hashedPassword = await bcrypt.hash(password, 10);
        
        // CORRECCIÓN CRÍTICA: CAMBIADO TRUE A FALSE
        // El usuario se registra pero NO ve videos hasta pagar
        const result = await pool.query(
            'INSERT INTO usuarios (nombre, email, password_hash, es_alumno_pago) VALUES ($1, $2, $3, FALSE) RETURNING id',
            [nombre, email, hashedPassword]
        );
        const nuevoUsuarioId = result.rows[0].id;
        const token = jwt.sign({ id: nuevoUsuarioId }, jwtSecret, { expiresIn: '7d' });

        // Opcional: Sincronizar con lista de LEADS (1) en lugar de ALUMNOS (2) hasta que paguen
        await syncBrevoContact(email, nombre, LIST_ID_LEADS); 

        res.status(201).json({ 
            message: 'Cuenta creada. Realiza el pago para acceder.',
            userId: nuevoUsuarioId,
            token: token,
            requierePago: true // Flag para el frontend
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error servidor.' });
    }
});

// RUTA 3: Login (Igual, pero aclaramos el mensaje del 403)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT id, password_hash, es_alumno_pago FROM usuarios WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user || !await bcrypt.compare(password, user.password_hash)) {
            return res.status(401).json({ error: 'Credenciales incorrectas.' });
        }

        const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '7d' });

        // Si NO pagó, devolvemos 200 pero con un aviso para que el frontend muestre el botón de pago
        // NOTA: Modifiqué esto para no rechazar el login, sino permitir entrar y ver la pantalla de "Pagar"
        if (user.es_alumno_pago !== true) {
             return res.json({
                message: 'Login exitoso. Pago pendiente.',
                userId: user.id,
                token: token,
                requierePago: true // IMPORTANTE: El frontend leerá esto
            });
        }

        res.json({
            message: 'Bienvenido.',
            userId: user.id,
            token: token,
            requierePago: false
        });

    } catch (error) { res.status(500).json({ error: 'Error interno.' }); }
});

// -------------------------------------------------------------------
// -- NUEVO: RUTAS DE MERCADO PAGO -----------------------------------
// -------------------------------------------------------------------

// RUTA: Crear Preferencia de Pago
app.post('/api/crear-pago', authenticateToken, async (req, res) => {
    try {
        const userId = req.userId;
        // Obtener email del usuario para MP
        const userResult = await pool.query('SELECT email, nombre FROM usuarios WHERE id = $1', [userId]);
        const user = userResult.rows[0];

        const preference = new Preference(client);
        
        const result = await preference.create({
            body: {
                items: [
                    {
                        id: 'curso-tamar-completo',
                        title: 'Acceso Completo - Escuela Tamar',
                        quantity: 1,
                        unit_price: 50000, // CAMBIAR POR TU PRECIO REAL (ARS para Argentina)
                        currency_id: 'ARS' // O 'USD' si tu cuenta MP lo permite
                    }
                ],
                payer: {
                    email: user.email,
                    name: user.nombre
                },
                back_urls: {
                    success: 'https://tamarescuela.netlify.app/videos.html?status=success',
                    failure: 'https://tamarescuela.netlify.app/videos.html?status=failure',
                    pending: 'https://tamarescuela.netlify.app/videos.html?status=pending'
                },
                auto_return: 'approved',
                notification_url: 'https://tamar-backend-api-gqy9.onrender.com/api/webhook/mercadopago', // URL DE TU BACKEND
                metadata: {
                    user_id: userId // IMPORTANTE: Para saber a quién activar cuando pague
                }
            }
        });

        res.json({ id: result.id, init_point: result.init_point }); // init_point es el link de pago
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al crear preferencia de pago' });
    }
});

// RUTA: Webhook (Donde MP avisa que pagaron)
app.post('/api/webhook/mercadopago', async (req, res) => {
    const topic = req.query.topic || req.query.type;
    const paymentId = req.query.id || req.query['data.id'];

    try {
        if (topic === 'payment') {
            const payment = new Payment(client);
            const paymentInfo = await payment.get({ id: paymentId });
            
            if (paymentInfo.status === 'approved') {
                const userId = paymentInfo.metadata.user_id; // Recuperamos el ID que enviamos antes
                
                if (userId) {
                    // ACTIVAR ALUMNO EN BASE DE DATOS
                    const result = await pool.query(
                        'UPDATE usuarios SET es_alumno_pago = TRUE WHERE id = $1 RETURNING email, nombre',
                        [userId]
                    );
                    
                    // MOVER A LISTA DE ALUMNOS (2) EN BREVO
                    if (result.rows.length > 0) {
                        const { email, nombre } = result.rows[0];
                        await syncBrevoContact(email, nombre, LIST_ID_ALUMNOS);
                        console.log(`Pago aprobado para usuario ${userId}. Activado.`);
                    }
                }
            }
        }
        res.status(200).send('OK');
    } catch (error) {
        console.error('Error webhook:', error);
        res.sendStatus(500);
    }
});

// ... (TUS RUTAS DE VIDEOS Y PROGRESO SIGUEN IGUAL) ...
// Solo recuerda que authenticateToken ya no bloqueará en el login, 
// pero SÍ debes mantener el bloqueo en /api/videos si user.es_alumno_pago es false.

app.get('/api/videos', authenticateToken, async (req, res) => {
    const userId = req.userId;
    
    // VERIFICACIÓN DE SEGURIDAD EXTRA
    const userCheck = await pool.query('SELECT es_alumno_pago FROM usuarios WHERE id = $1', [userId]);
    if (!userCheck.rows[0].es_alumno_pago) {
        return res.status(403).json({ error: 'Debes comprar el curso para ver los videos.', requierePago: true });
    }

    // ... (El resto de tu lógica de videos sigue igual) ...
    // ...
});

// ... (Resto del archivo y app.listen) ...
app.listen(port, () => {
    console.log(`Servidor corriendo en puerto ${port}`);
});
