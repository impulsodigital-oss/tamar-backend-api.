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

// MERCADO PAGO: Configuración Cliente
// Asegúrate de tener MP_ACCESS_TOKEN en las variables de Render
const client = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });

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
        if (!response.ok) {
            console.warn(`Brevo Warning: ${await response.text()}`);
        }
    } catch (error) { console.error('Error Brevo:', error); }
}

// Middlewares
app.use(express.json());
app.use(cors());

// Configuración DB
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// -------------------------------------------------------------------
// -- INICIALIZACIÓN DE BASE DE DATOS (AUTO-CREACIÓN DE TABLAS)
// -------------------------------------------------------------------
pool.connect(async (err, client, release) => {
    if (err) {
        console.error('¡ADVERTENCIA! Error al conectar a la base de datos:', err.stack);
        return;
    }
    
    try {
        // CREAR TABLA DE CLASES EN VIVO AUTOMÁTICAMENTE SI NO EXISTE
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
        console.log('✅ Tabla "clases_en_vivo" verificada/creada exitosamente.');
        
        // Insertar una clase de prueba si la tabla está vacía (para evitar pantallas vacías)
        const checkData = await client.query('SELECT COUNT(*) FROM clases_en_vivo');
        if (parseInt(checkData.rows[0].count) === 0) {
            await client.query(`
                INSERT INTO clases_en_vivo (titulo, profesor, fecha_hora, link_zoom, descripcion)
                VALUES ('Clase de Bienvenida', 'Sofía', NOW() + INTERVAL '1 day', 'https://zoom.us/j/pendientesofia', 'Introducción al método Tamar.');
            `);
            console.log('✅ Clase de prueba insertada.');
        }

    } catch (tableErr) {
        console.error('Error al inicializar tablas:', tableErr);
    } finally {
        release();
        console.log('Conexión exitosa a PostgreSQL (Render DB)!');
    }
});

// -------------------------------------------------------------------
// -- MIDDLEWARES DE AUTENTICACIÓN
// -------------------------------------------------------------------
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

const authenticateAdmin = (req, res, next) => {
    // Solo permite acceso al ID 1 (Sofía)
    if (req.userId != 1) { 
        return res.status(403).json({ error: 'Acceso denegado. Se requiere ser administrador.' });
    }
    next();
};

// -------------------------------------------------------------------
// -- RUTAS PÚBLICAS
// -------------------------------------------------------------------

// RUTA 1: Leads
app.post('/api/leads', async (req, res) => {
    const { nombre, email } = req.body;
    if (!nombre || !email) return res.status(400).json({ error: 'Datos incompletos.' });

    try {
        const queryText = `
            INSERT INTO usuarios (nombre, email, es_alumno_pago) 
            VALUES ($1, $2, FALSE) 
            ON CONFLICT (email) DO UPDATE SET nombre = EXCLUDED.nombre 
            RETURNING id
        `;
        const result = await pool.query(queryText, [nombre, email]);
        await syncBrevoContact(email, nombre, LIST_ID_LEADS);
        res.status(201).json({ message: 'Lead registrado.', userId: result.rows[0].id });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error servidor.' });
    }
});

// RUTA 2: Registro (Cuenta PENDIENTE DE PAGO)
app.post('/api/registro', async (req, res) => {
    const { nombre, email, password } = req.body;
    if (!nombre || !email || !password) return res.status(400).json({ error: 'Datos incompletos.' });

    try {
        const existingUser = await pool.query('SELECT id FROM usuarios WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) return res.status(409).json({ error: 'Email registrado.' });

        const hashedPassword = await bcrypt.hash(password, 10);
        
        // IMPORTANTE: Se crea como FALSE (No pago)
        const result = await pool.query(
            'INSERT INTO usuarios (nombre, email, password_hash, es_alumno_pago) VALUES ($1, $2, $3, FALSE) RETURNING id',
            [nombre, email, hashedPassword]
        );
        const nuevoUsuarioId = result.rows[0].id;
        const token = jwt.sign({ id: nuevoUsuarioId }, jwtSecret, { expiresIn: '7d' });

        // Sincronizar como Lead hasta que pague
        await syncBrevoContact(email, nombre, LIST_ID_LEADS);

        res.status(201).json({ 
            message: 'Cuenta creada. Realiza el pago para acceder.',
            userId: nuevoUsuarioId,
            token: token,
            requierePago: true
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error servidor.' });
    }
});

// RUTA 3: Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT id, nombre, password_hash, es_alumno_pago FROM usuarios WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user || !await bcrypt.compare(password, user.password_hash)) {
            return res.status(401).json({ error: 'Credenciales incorrectas.' });
        }

        const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '7d' });

        // Si NO pagó, permitimos login pero enviamos flag requierePago
        if (user.es_alumno_pago !== true) {
             return res.json({
                message: 'Login exitoso. Pago pendiente.',
                userId: user.id,
                nombre: user.nombre,
                token: token,
                requierePago: true
            });
        }

        res.json({
            message: `Bienvenido ${user.nombre}.`,
            userId: user.id,
            nombre: user.nombre,
            token: token,
            requierePago: false
        });

    } catch (error) { res.status(500).json({ error: 'Error interno.' }); }
});

// -------------------------------------------------------------------
// -- RUTAS DE MERCADO PAGO
// -------------------------------------------------------------------

app.post('/api/crear-pago', authenticateToken, async (req, res) => {
    try {
        const userId = req.userId;
        const userResult = await pool.query('SELECT email, nombre FROM usuarios WHERE id = $1', [userId]);
        const user = userResult.rows[0];

        const preference = new Preference(client);
        
        const result = await preference.create({
            body: {
                items: [{
                    id: 'curso-tamar-completo',
                    title: 'Acceso Completo - Escuela Tamar',
                    quantity: 1,
                    unit_price: 50000, // ARS
                    currency_id: 'ARS'
                }],
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
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al crear pago' });
    }
});

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
                    const result = await pool.query(
                        'UPDATE usuarios SET es_alumno_pago = TRUE WHERE id = $1 RETURNING email, nombre',
                        [userId]
                    );
                    if (result.rows.length > 0) {
                        const { email, nombre } = result.rows[0];
                        await syncBrevoContact(email, nombre, LIST_ID_ALUMNOS);
                        console.log(`Pago aprobado: Usuario ${userId} activado.`);
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

// -------------------------------------------------------------------
// -- RUTAS PROTEGIDAS (ALUMNOS)
// -------------------------------------------------------------------

// RUTA 4: Obtener Videos (Con bloqueo si no pagó)
app.get('/api/videos', authenticateToken, async (req, res) => {
    const userId = req.userId;
    
    try {
        // 1. Verificar Pago
        const userCheck = await pool.query('SELECT es_alumno_pago FROM usuarios WHERE id = $1', [userId]);
        if (!userCheck.rows[0] || !userCheck.rows[0].es_alumno_pago) {
            return res.status(403).json({ error: 'Debes comprar el curso.', requierePago: true });
        }

        // 2. Obtener Videos
        const videosResult = await pool.query('SELECT * FROM videos ORDER BY modulo, orden ASC');
        const videos = videosResult.rows;

        // 3. Obtener Progreso
        const progresoResult = await pool.query('SELECT video_id FROM progreso_alumnos WHERE usuario_id = $1', [userId]);
        const completedVideoIds = new Set(progresoResult.rows.map(row => row.video_id));

        const videosWithStatus = videos.map(video => ({
            ...video,
            completado: completedVideoIds.has(video.id)
        }));

        res.json({ videos: videosWithStatus });
    } catch (error) {
        console.error('Error videos:', error);
        res.status(500).json({ error: 'Error servidor.' });
    }
});

// RUTA 5: Marcar Progreso
app.post('/api/progreso', authenticateToken, async (req, res) => {
    const userId = req.userId;
    const { videoId } = req.body;
    if (!videoId) return res.status(400).json({ error: 'Falta videoId.' });

    try {
        const result = await pool.query(
            'INSERT INTO progreso_alumnos (usuario_id, video_id, fecha_completado) VALUES ($1, $2, NOW()) RETURNING id',
            [userId, videoId]
        );
        res.status(201).json({ message: 'Progreso guardado.', progresoId: result.rows[0].id });
    } catch (error) {
        if (error.code === '23505') { // Unique constraint violation
            return res.status(409).json({ error: 'Ya completado.' });
        }
        res.status(500).json({ error: 'Error servidor.' });
    }
});

// RUTA 6: Clases en Vivo (Ahora funciona gracias al init DB)
app.get('/api/clases-en-vivo', authenticateToken, async (req, res) => {
    try {
        // Verificar pago también aquí
        const userCheck = await pool.query('SELECT es_alumno_pago FROM usuarios WHERE id = $1', [req.userId]);
        if (!userCheck.rows[0].es_alumno_pago) {
            return res.status(403).json({ error: 'Requiere pago.', requierePago: true });
        }

        const result = await pool.query('SELECT * FROM clases_en_vivo ORDER BY fecha_hora ASC');
        res.json({ clases: result.rows });
    } catch (error) {
        console.error('Error clases:', error);
        res.status(500).json({ error: 'Error servidor.' });
    }
});

// -------------------------------------------------------------------
// -- RUTAS ADMIN
// -------------------------------------------------------------------

app.get('/api/admin/usuarios-activos', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, nombre, email FROM usuarios WHERE es_alumno_pago = TRUE ORDER BY id DESC');
        res.json({ alumnos: result.rows });
    } catch (error) {
        res.status(500).json({ error: 'Error servidor.' });
    }
});

app.get('/api/admin/leads-pendientes', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, nombre, email, fecha_registro FROM usuarios WHERE es_alumno_pago = FALSE ORDER BY id DESC');
        res.json({ leads: result.rows });
    } catch (error) {
        res.status(500).json({ error: 'Error servidor.' });
    }
});

// Start Server
app.listen(port, () => {
    console.log(`Servidor corriendo en puerto ${port}`);
});
