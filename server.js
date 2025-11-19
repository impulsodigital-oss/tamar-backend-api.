// Cargar variables de entorno desde el archivo .env
require('dotenv').config();

const express = require('express');
const { Pool } = require('pg'); 
const cors = require('cors'); 
const bcrypt = require('bcryptjs'); // ¡CORRECTO! Usamos bcryptjs
const jwt = require('jsonwebtoken'); 
const fetch = require('node-fetch'); 

const app = express();
const port = process.env.PORT || 3000; 
const jwtSecret = process.env.JWT_SECRET; 

// CONFIGURACIÓN DE BREVO (Necesitas la variable BREVO_API_KEY en Render)
const BREVO_API_KEY = process.env.BREVO_API_KEY; 
const LIST_ID_LEADS = 1; 
const LIST_ID_ALUMNOS = 2; 


// -------------------------------------------------------------------
// --       FUNCIÓN DE SINCRONIZACIÓN BREVO                         -----
// -------------------------------------------------------------------

async function syncBrevoContact(email, nombre, listId) {
    if (!BREVO_API_KEY) {
        console.warn('BREVO_API_KEY no configurada. Omitiendo sincronización con Brevo.');
        return;
    }

    try {
        const response = await fetch('https://api.brevo.com/v3/contacts', {
            method: 'POST',
            headers: {
                // **ESTA CLAVE DEBE COINCIDIR EXACTAMENTE CON LA DE RENDER**
                'api-key': BREVO_API_KEY, 
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: email,
                listIds: [listId],
                updateEnabled: true, 
                attributes: {
                    NOMBRE: nombre
                }
            })
        });

        if (response.ok) {
            console.log(`Contacto ${email} sincronizado con Brevo en la lista ${listId}.`);
        } else {
            const errorText = await response.text();
            console.error(`Error al sincronizar con Brevo (Status ${response.status}): ${errorText}`);
        }
    } catch (error) {
        console.error('Error de red al llamar a la API de Brevo:', error);
    }
}


// Middlewares
app.use(express.json()); 
app.use(cors()); 

// Configuración de la conexión a la base de datos (usando la URL interna de Render)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Probar la conexión a la base de datos
pool.connect((err, client, release) => {
    if (err) {
        console.error('¡ADVERTENCIA! Error al conectar a la base de datos:', err.stack);
        console.error('El servidor Express intentará iniciarse, pero las rutas de BD fallarán.');
        return;
    }
    release();
    console.log('Conexión exitosa a PostgreSQL (Render DB)!'); 
});


// -------------------------------------------------------------------
// --        MIDDLEWARE DE AUTENTICACIÓN                          -----
// -------------------------------------------------------------------
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Espera "Bearer TOKEN"

    if (token == null) {
        return res.status(401).json({ error: 'Acceso denegado. Token no proporcionado.' });
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido o expirado.' });
        }
        // Agrega el ID del usuario al objeto request para usarlo en las rutas protegidas
        req.userId = user.id; 
        next();
    });
};


// -------------------------------------------------------------------
// --        RUTAS PÚBLICAS                                       -----
// -------------------------------------------------------------------

// RUTA 1: Captura de Leads (Guía Gratuita)
app.post('/api/leads', async (req, res) => {
    const { nombre, email } = req.body;

    if (!nombre || !email) {
        return res.status(400).json({ error: 'Nombre y email son obligatorios.' });
    }

    try {
        let nuevoUsuarioId;

        // 1. Insertar o actualizar Lead (ON CONFLICT maneja si el email ya existe)
        const queryText = `
            INSERT INTO usuarios (nombre, email, es_alumno_pago) 
            VALUES ($1, $2, FALSE) 
            ON CONFLICT (email) 
            DO UPDATE SET nombre = EXCLUDED.nombre 
            RETURNING id
        `;
        const result = await pool.query(queryText, [nombre, email]); 
        nuevoUsuarioId = result.rows[0].id;
        
        // 2. Sincronizar con Brevo
        await syncBrevoContact(email, nombre, LIST_ID_LEADS);

        res.status(201).json({ 
            message: 'Lead registrado exitosamente. Revisa tu email para la guía.',
            userId: nuevoUsuarioId 
        });

    } catch (error) {
        console.error('Error al registrar lead:', error.stack);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});


// RUTA 2: Registro de Alumno Pago
app.post('/api/registro', async (req, res) => {
    const { nombre, email, password } = req.body;

    if (!nombre || !email || !password) {
        return res.status(400).json({ error: 'Nombre, email y contraseña son obligatorios.' });
    }

    try {
        // 1. Verificar si el usuario ya existe
        const existingUser = await pool.query('SELECT id FROM usuarios WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'El email ya está registrado.' });
        }

        // 2. Encriptar la contraseña (usando bcryptjs)
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // 3. Insertar el nuevo alumno (es_alumno_pago = TRUE)
        const result = await pool.query(
            'INSERT INTO usuarios (nombre, email, password_hash, es_alumno_pago) VALUES ($1, $2, $3, TRUE) RETURNING id',
            [nombre, email, hashedPassword]
        );
        const nuevoUsuarioId = result.rows[0].id;

        // 4. Generar el token JWT
        const token = jwt.sign({ id: nuevoUsuarioId }, jwtSecret, { expiresIn: '7d' });

        // 5. Sincronizar con Brevo 
        await syncBrevoContact(email, nombre, LIST_ID_ALUMNOS);

        res.status(201).json({ 
            message: 'Registro exitoso. Bienvenido a Tamar!',
            userId: nuevoUsuarioId,
            token: token 
        });

    } catch (error) {
        console.error('Error al registrar usuario:', error.stack);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});


// RUTA 3: Inicio de Sesión
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email y contraseña son obligatorios.' });
    }

    try {
        // 1. Buscar el usuario
        const result = await pool.query('SELECT id, password_hash, es_alumno_pago FROM usuarios WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user || !user.password_hash) {
            return res.status(401).json({ error: 'Email o contraseña incorrectos.' });
        }

        // 2. Verificar la contraseña (usando bcryptjs.compare)
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return res.status(401).json({ error: 'Email o contraseña incorrectos.' });
        }

        // 3. Verificar si es alumno pago (IMPORTANTE: Esto causa el 403 si el usuario no es pago)
        if (user.es_alumno_pago !== true) {
             return res.status(403).json({ error: 'Tu cuenta no está activa para acceder a los cursos. Contacta a soporte.' });
        }

        // 4. Generar el token JWT
        const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '7d' });

        res.json({
            message: 'Inicio de sesión exitoso.',
            userId: user.id,
            token: token
        });

    } catch (error) {
        console.error('Error durante el login:', error.stack);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});


// -------------------------------------------------------------------
// --        RUTAS PROTEGIDAS (Requieren Token JWT)               -----
// -------------------------------------------------------------------

// RUTA 4: Obtener lista de videos y progreso del usuario
app.get('/api/videos', authenticateToken, async (req, res) => {
    const userId = req.userId; // ID del usuario obtenido del token JWT

    try {
        // 1. Obtener la lista completa de videos
        const videosResult = await pool.query('SELECT * FROM videos ORDER BY modulo, orden ASC');
        const videos = videosResult.rows;

        // 2. Obtener el progreso del usuario (IDs de videos completados)
        const progresoResult = await pool.query(
            'SELECT video_id FROM progreso_alumnos WHERE usuario_id = $1',
            [userId]
        );
        const completedVideoIds = new Set(progresoResult.rows.map(row => row.video_id));

        // 3. Combinar los datos
        const videosWithStatus = videos.map(video => ({
            ...video,
            completado: completedVideoIds.has(video.id)
        }));

        res.json({ videos: videosWithStatus });

    } catch (error) {
        console.error('Error al obtener videos:', error.stack);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// RUTA 5: Marcar progreso de video
app.post('/api/progreso', authenticateToken, async (req, res) => {
    const userId = req.userId;
    const { videoId } = req.body;

    if (!videoId) {
        return res.status(400).json({ error: 'El ID del video es obligatorio.' });
    }

    try {
        // La restricción UNIQUE en la BD maneja el caso de duplicados
        const result = await pool.query(
            'INSERT INTO progreso_alumnos (usuario_id, video_id, fecha_completado) VALUES ($1, $2, NOW()) RETURNING id',
            [userId, videoId]
        );
        console.log(`Usuario ${userId} marcó el video ${videoId} como completado.`);
        res.status(201).json({ message: 'Progreso registrado exitosamente.', progresoId: result.rows[0].id });

    } catch (error) {
        // Manejar el caso de que el video ya esté marcado como completado
        if (error.code === '23505' && error.constraint === 'progreso_alumnos_usuario_id_video_id_key') {
            return res.status(409).json({ error: 'Este video ya ha sido marcado como completado por este usuario.' });
        }
        console.error('Error al registrar progreso:', error.stack);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});


// -------------------------------------------------------------------
// --        INICIO DEL SERVIDOR                                  -----
// -------------------------------------------------------------------
app.listen(port, () => {
    console.log(`Servidor backend de Tamar corriendo en http://localhost:${port}`);
    
    // Verificación de variables clave
    if (!process.env.DATABASE_URL) {
        console.error("¡ALERTA! DATABASE_URL no está configurada.");
    }
    if (!process.env.JWT_SECRET) {
        console.error("¡ALERTA! JWT_SECRET no está configurada.");
    }
    if (!BREVO_API_KEY) {
        console.warn("¡ADVERTENCIA! BREVO_API_KEY no está configurada. La sincronización de marketing está desactivada.");
    }
});

