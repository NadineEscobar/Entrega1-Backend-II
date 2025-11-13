// src/config/passportConfig.js
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import User from '../dao/models/userModel.js';
import { isValidPassword } from '../utils/bcryptUtil.js';

export const initializePassport = (jwtSecret) => {
  // Estrategia local (login con email y contraseña)
  passport.use('login', new LocalStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
      session: false
    },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email });
        if (!user) return done(null, false, { message: 'Usuario no encontrado' });
        if (!isValidPassword(user, password)) return done(null, false, { message: 'Contraseña incorrecta' });
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  ));

  // Estrategia JWT (para verificar token en rutas protegidas)
  const opts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: jwtSecret
  };

  passport.use('jwt', new JwtStrategy(opts, async (payload, done) => {
    try {
      const user = await User.findById(payload.sub).select('-password');
      if (user) return done(null, user);
      return done(null, false);
    } catch (error) {
      return done(error, false);
    }
  }));
};