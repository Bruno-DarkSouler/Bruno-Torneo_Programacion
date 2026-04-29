const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config();
const app = express();
app.use(cors());
app.use(express.json());



// "BASE DE DATOS" en memoria (simple)
let usuarios = [];



// ========== MIDDLEWARE DE AUTENTICACIÓN ==========
function verificarToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token requerido' });
    }
    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_ULTRA_SECRETO);
        req.usuarioId = decoded.id;
        req.usuarioRol = decoded.rol;
        next();
    } catch (error) {
        res.status(403).json({ error: 'Token inválido' });
    }
}



    // ========== ENDPOINTS ==========
    // 1. REGISTRO
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, rol = 'participante' } = req.body;

    // Validación simple
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Faltan datos' });
    }

    // Verificar si ya existe
    if (usuarios.find(u => u.email === email)) {
        return res.status(400).json({ error: 'Email ya registrado' });
    }

    // Encriptar password
    const hashedPassword = await bcrypt.hash(password, 10);
    // Crear usuario
    const nuevoUsuario = {
        id: Date.now().toString(), // ID simple
        username,
        email,
        password: hashedPassword,
        rol,
        puntuacionTotal: 0
    };

    usuarios.push(nuevoUsuario);

    // Generar token
    const token = jwt.sign({
        id: nuevoUsuario.id, rol: nuevoUsuario.rol },
        process.env.JWT_ULTRA_SECRETO,
        { expiresIn: '24h' }
    );

    res.status(201).json({
        message: 'Registro exitoso',
        token,
        usuario: { id: nuevoUsuario.id, username, email, rol }
    });

    } catch (error) {
        res.status(500).json({ error: 'Error en el servidor' });
    }
});




    // 2. LOGIN
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email y password requeridos' });
        }

        const usuario = usuarios.find(u => u.email === email);
        if (!usuario) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        const passwordValida = await bcrypt.compare(password, usuario.password);

        if (!passwordValida) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        const token = jwt.sign(
            { id: usuario.id, rol: usuario.rol },
            process.env.JWT_ULTRA_SECRETO,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login exitoso',
            token,
            usuario: { id: usuario.id, username: usuario.username, email: usuario.email, rol: usuario.rol }
        });

    } catch (error) {
        res.status(500).json({ error: 'Error en el servidor' });
    }
});


    // 3. PERFIL (ruta protegida)
app.get('/api/auth/me', verificarToken, (req, res) => {
    const usuario = usuarios.find(u => u.id === req.usuarioId);

    if (!usuario) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json({
        id: usuario.id,
        username: usuario.username,
        email: usuario.email,
        rol: usuario.rol,
        puntuacionTotal: usuario.puntuacionTotal
    });
});





// 4. RUTA ADMIN (solo para probar roles)
app.get('/api/admin/solo-admin', verificarToken, (req, res) => {
    if (req.usuarioRol !== 'admin') {
        return res.status(403).json({ error: 'Se necesita rol admin' });
    }

    res.json({ message: 'Bienvenido admin' });
});



        // 5. Inicio
app.get('/', (req, res) => {
    res.json({
        message: 'CodeArena API funcionando',
        endpoints: [
        'POST /api/auth/register',
        'POST /api/auth/login',
        'GET /api/auth/me (requiere token)',
        'GET /api/admin/solo-admin (requiere token y rol admin)'
        ]
    });
});


        // Iniciar servidor
const PORT = 3000;
    app.listen(PORT, () => {
    console.log(`Servidor en http://localhost:${PORT}`);
    console.log('isto para probar con Thunder Client');
});