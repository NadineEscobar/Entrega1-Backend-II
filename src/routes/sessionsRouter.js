// src/routes/sessionsRouter.js
import express from 'express';
import passport from 'passport';
import jwt from 'jsonwebtoken';
import User from '../dao/models/userModel.js';
import { createHash } from '../utils/bcryptUtil.js';

const router = express.Router();

// 🧩 Registro
router.post('/register', async (req, res) => {
  try {
    const { first_name, last_name, email, age, password } = req.body;

    if (!first_name || !last_name || !email || !password)
      return res.status(400).json({ error: 'Faltan campos obligatorios' });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ error: 'El usuario ya existe' });

    const newUser = new User({
      first_name,
      last_name,
      email,
      age,
      password: createHash(password)
    });

    await newUser.save();

    const safeUser = newUser.toObject();
    delete safeUser.password;

    res.status(201).json({ message: 'Usuario creado', user: safeUser });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// 🧩 Login con generación de JWT + cookie
router.post('/login', (req, res, next) => {
  passport.authenticate('login', { session: false }, (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.status(401).json({ error: info?.message || 'Credenciales inválidas' });

    const payload = { sub: user._id, email: user.email, role: user.role };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    // 🧠 Guardamos el token en una cookie
    res.cookie('jwtCookie', token, {
      httpOnly: true,
      secure: false, // ⚠️ En producción usar true (HTTPS)
      maxAge: 60 * 60 * 1000 // 1 hora
    });

    res.json({ message: 'Login exitoso', token });
  })(req, res, next);
});

// 🧩 Ruta protegida (current)
router.get('/current', passport.authenticate('jwt', { session: false }), (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Token inválido o expirado' });
  res.json({ status: 'success', user: req.user });
});

// 🧩 Logout (opcional)
router.post('/logout', (req, res) => {
  res.clearCookie('jwtCookie');
  res.json({ message: 'Sesión cerrada correctamente' });
});

export default router;