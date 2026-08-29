const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;

const app = express();

// Middlewares
app.use(express.json());
app.use(cors());

// Session Middleware für Passport
app.use(session({
  secret: process.env.SESSION_SECRET || 'scripthub_geheimes_session_passwort',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

const SECRET_KEY = process.env.JWT_SECRET || "mein_geheimes_passwort_key";

// Datenbank initialisieren (Persistent in /tmp für Render)
let db;
try {
  db = new Database('/tmp/database.sqlite');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT);
    CREATE TABLE IF NOT EXISTS scripts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, code TEXT, author TEXT);
  `);
  console.log("Datenbank erfolgreich verbunden!");
} catch (err) {
  console.error("Fehler bei der Datenbank-Initialisierung:", err);
}

// Passport Serialisierung
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// --- OAuth Strategien ---

// 1. Google OAuth
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://scripthub-api.onrender.com/api/auth/google/callback"
    },
    (accessToken, refreshToken, profile, done) => {
      const username = profile.displayName ? profile.displayName.replace(/\s+/g, '') : `GoogleUser_${profile.id}`;
      return done(null, { username, provider: 'google' });
    }
  ));
}

// 2. GitHub OAuth
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: "https://scripthub-api.onrender.com/api/auth/github/callback"
    },
    (accessToken, refreshToken, profile, done) => {
      const username = profile.username || `GitHubUser_${profile.id}`;
      return done(null, { username, provider: 'github' });
    }
  ));
}

// --- OAuth Routen ---

// Google
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/api/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect(`https://mtheo3103-hash.github.io/scripthub-backend/?user=${req.user.username}`);
  }
);

// GitHub
app.get('/api/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
app.get('/api/auth/github/callback', 
  passport.authenticate('github', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect(`https://mtheo3103-hash.github.io/scripthub-backend/?user=${req.user.username}`);
  }
);

// --- Reguläre API Routen ---

// Registrierung
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Benutzername und Passwort erforderlich." });
  }
  
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
    stmt.run(username, hashedPassword);
    res.json({ message: "Account erfolgreich erstellt!" });
  } catch (e) {
    res.status(400).json({ error: "Benutzername bereits vergeben." });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
  const user = stmt.get(username);

  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ username: user.username }, SECRET_KEY);
    res.json({ token, username: user.username });
  } else {
    res.status(400).json({ error: "Ungültige Anmeldedaten." });
  }
});

// Skript hochladen
app.post('/api/scripts', (req, res) => {
  const { title, code, author } = req.body;
  if (!title || !code) {
    return res.status(400).json({ error: "Titel und Code dürfen nicht leer sein." });
  }
  const stmt = db.prepare('INSERT INTO scripts (title, code, author) VALUES (?, ?, ?)');
  stmt.run(title, code, author || 'Anonym');
  res.json({ message: "Skript erfolgreich hochgeladen!" });
});

// Alle Skripte abrufen
app.get('/api/scripts', (req, res) => {
  const stmt = db.prepare('SELECT * FROM scripts ORDER BY id DESC');
  const scripts = stmt.all();
  res.json(scripts);
});

// Server starten
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Backend läuft erfolgreich auf Port ${PORT}`);
});
