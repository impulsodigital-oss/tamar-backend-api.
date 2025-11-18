// Cargar variables de entorno desde el archivo .env
require('dotenv').config();

const express = require('express');
const { Pool } = require('pg'); // Para conectarnos a PostgreSQL
const cors = require('cors'); // Para permitir peticiones desde el frontend (Netlify)
const bcrypt = require('bcrypt'); // Para encriptar y verificar contraseñas
const jwt = require('jsonwebtoken'); // Para tokens de autenticación

const app = express();
const port = process.env.PORT; // Obtenemos el puerto del archivo .env
const jwtSecret = process.env.JWT_SECRET; // Clave secreta para JWT desde .env

// Middlewares
app.use(express.json()); // Para parsear cuerpos de solicitud JSON
app.use(cors()); // Configurar CORS para permitir solicitudes desde cualquier origen (luego lo restringiremos)

// Configuración de la conexión a la base de datos
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // NECESARIO para conexiones SSL a Supabase desde entorno local o Render
    }
});

// Probar la conexión a la base de datos (con manejo de error para desarrollo local)
pool.connect((err, client, release) => {
    if (err) {
        console.error('¡ADVERTENCIA! Error al conectar a la base de datos:', err.stack);
        console.error('El servidor Express intentará iniciarse, pero las rutas de BD fallarán en local hasta resolver el ENOTFOUND.');
    } else {
        console.log('Conexión exitosa a PostgreSQL (Supabase)!');
        release(); // Libera el cliente de la base de datos
    }
});

// -------------------------------------------------------------------
// --        MIDDLEWARE DE AUTENTICACIÓN (JWT)                   -----
// -------------------------------------------------------------------
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    // El token viene como "Bearer TOKEN_AQUI"
    const token = authHeader && authHeader.split(' ')[1]; 

    if (token == null) {
        return res.status(401).json({ error: 'Acceso denegado. No se proporcionó token de autenticación.' });
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            // El token no es válido o ha expirado
            return res.status(403).json({ error: 'Token de autenticación inválido o expirado.' });
        }
        req.user = user; // Guarda la información del usuario en la solicitud
        next(); // Continúa con la siguiente función (el controlador de la ruta)
    });
}


// -------------------------------------------------------------------
// --        DEFINICIÓN DE ENDPOINTS DE TU API                   -----
// -------------------------------------------------------------------

// ENDPOINT 1: POST /api/leads
// Para capturar un nuevo lead (interesado en la guía gratuita)
app.post('/api/leads', async (req, res) => {
    const { nombre, email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'El email es obligatorio.' });
    }

    try {
        const result = await pool.query(
            'INSERT INTO usuarios (nombre, email, es_alumno_pago) VALUES ($1, $2, FALSE) RETURNING id',
            [nombre, email]
        );
        const nuevoUsuarioId = result.rows[0].id;
        console.log(`Nuevo lead registrado con ID: ${nuevoUsuarioId}`);

        // Aquí iría el código real para hacer una solicitud POST a la API de Brevo
        console.log(`Simulando envío a Brevo para email: ${email}`);

        res.status(201).json({ 
            message: 'Lead registrado exitosamente. Revisa tu email para la guía.',
            userId: nuevoUsuarioId 
        });

    } catch (error) {
        if (error.code === '23505' && error.constraint === 'usuarios_email_key') {
            return res.status(409).json({ error: 'Este email ya está registrado.' });
        }
        console.error('Error al registrar lead:', error.stack);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// ENDPOINT 2: POST /api/registro
// Para registrar un nuevo alumno
app.post('/api/registro', async (req, res) => {
    const { nombre, email, password } = req.body;

    if (!nombre || !email || !password) {
        return res.status(400).json({ error: 'Nombre, email y contraseña son obligatorios.' });
    }

    try {
        const saltRounds = 10; 
        const passwordHash = await bcrypt.hash(password, saltRounds);

        const result = await pool.query(
            'INSERT INTO usuarios (nombre, email, password_hash, es_alumno_pago) VALUES ($1, $2, $3, TRUE) RETURNING id',
            [nombre, email, passwordHash]
        );
        const nuevoUsuarioId = result.rows[0].id;

        const token = jwt.sign(
            { userId: nuevoUsuarioId, email: email },
            jwtSecret, 
            { expiresIn: '1h' } 
        );

        console.log(`Nuevo alumno registrado con ID: ${nuevoUsuarioId}`);

        res.status(201).json({ 
            message: 'Registro exitoso. Bienvenido a Tamar!',
            userId: nuevoUsuarioId,
            token: token 
        });

    } catch (error) {
        if (error.code === '23505' && error.constraint === 'usuarios_email_key') {
            return res.status(409).json({ error: 'Este email ya está registrado.' });
        }
        console.error('Error al registrar alumno:', error.stack);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});


// NUEVO ENDPOINT 3: POST /api/login
// Para que un alumno inicie sesión
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email y contraseña son obligatorios.' });
    }

    try {
        // 1. Buscar el usuario por email
        const result = await pool.query('SELECT id, nombre, email, password_hash FROM usuarios WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(400).json({ error: 'Email o contraseña incorrectos.' });
        }

        // 2. Comparar la contraseña proporcionada con el hash guardado
        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        if (!passwordMatch) {
            return res.status(400).json({ error: 'Email o contraseña incorrectos.' });
        }

        // 3. Generar un Token de Autenticación (JWT) si las credenciales son válidas
        const token = jwt.sign(
            { userId: user.id, email: user.email, nombre: user.nombre },
            jwtSecret,
            { expiresIn: '1h' }
        );

        console.log(`Usuario ${user.email} ha iniciado sesión.`);

        res.status(200).json({ 
            message: 'Inicio de sesión exitoso.',
            userId: user.id,
            token: token 
        });

    } catch (error) {
        console.error('Error al iniciar sesión:', error.stack);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});


// NUEVO ENDPOINT 4: GET /api/videos (PROTEGIDO)
// Para que los alumnos autenticados puedan obtener la lista de videos
app.get('/api/videos', authenticateToken, async (req, res) => {
    try {
        const videosResult = await pool.query(
            'SELECT id, titulo_corto, titulo_completo, video_id_panda, modulo, orden FROM videos ORDER BY modulo, orden'
        );
        const videos = videosResult.rows;

        // Aquí también podríamos obtener el progreso del usuario req.user.userId
        // y adjuntarlo a cada video, pero por ahora solo retornamos los videos.

        res.status(200).json({ videos: videos });

    } catch (error) {
        console.error('Error al obtener videos:', error.stack);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});


// NUEVO ENDPOINT 5: POST /api/progreso (PROTEGIDO)
// Para que un alumno autenticado marque un video como completado
app.post('/api/progreso', authenticateToken, async (req, res) => {
    const { videoId } = req.body; // Se espera que el frontend envíe el ID del video
    const userId = req.user.userId; // El ID del usuario viene del token autenticado

    if (!videoId) {
        return res.status(400).json({ error: 'El ID del video es obligatorio.' });
    }

    try {
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
// --        INICIO DEL SERVIDOR                                 -----
// -------------------------------------------------------------------
app.listen(port, () => {
    console.log(`Servidor backend de Tamar corriendo en http://localhost:${port}`);
    if (!pool._connected) { 
        console.warn('ADVERTENCIA: La base de datos no pudo conectar. Las rutas que dependan de la BD fallarán.');
    }
});