const express = require('express');
const passport = require('passport');
const bcrypt = require('bcrypt');
const LocalStrategy = require('passport-local').Strategy;
const GitHubStrategy = require('passport-github').Strategy;
const session = require('express-session');

const app = express();

// Configuración de express
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'your-secret-key', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// Configuración de la estrategia local (username y password)
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      // Aquí debes implementar la lógica para buscar el usuario en tu base de datos
      const user = await findUserByUsername(username);

      if (!user) {
        return done(null, false, { message: 'Usuario no encontrado' });
      }

      const isValidPassword = await bcrypt.compare(password, user.password);

      if (!isValidPassword) {
        return done(null, false, { message: 'Contraseña incorrecta' });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

// Configuración de la estrategia de GitHub
passport.use(new GitHubStrategy({
  clientID: 'your-github-client-id',
  clientSecret: 'your-github-client-secret',
  callbackURL: 'http://localhost:3000/auth/github/callback'
},
async (accessToken, refreshToken, profile, done) => {
  // Aquí debes implementar la lógica para buscar o crear el usuario en tu base de datos
  const user = await findOrCreateUserByGitHubProfile(profile);

  return done(null, user);
}));

// Serialización del usuario para almacenar en la sesión
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialización del usuario para obtenerlo de la sesión
passport.deserializeUser(async (id, done) => {
  try {
    // Aquí debes implementar la lógica para buscar el usuario por su ID en tu base de datos
    const user = await findUserById(id);

    if (!user) {
      return done(null, false);
    }

    return done(null, user);
  } catch (error) {
    return done(error);
  }
});

// Rutas de autenticación local
app.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/login',
  failureFlash: true
}));

// Ruta de autenticación con GitHub
app.get('/auth/github', passport.authenticate('github'));

app.get('/auth/github/callback',
  passport.authenticate('github', { successRedirect: '/dashboard', failureRedirect: '/login' })
);

// Ruta para verificar si el usuario está autenticado
app.get('/dashboard', (req, res) => {
  if (req.isAuthenticated()) {
    res.send('Bienvenido a tu dashboard');
  } else {
    res.redirect('/login');
  }
});

// Inicia el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor iniciado en http://localhost:${PORT}`);
});
