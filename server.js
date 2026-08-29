const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = "mein_geheimes_passwort_key";

// Datenbank initialisieren
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

// 1. Registrierung
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

// 2. Login
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

// 3. Skript hochladen
app.post('/api/scripts', (req, res) => {
  const { title, code, author } = req.body;
  if (!title || !code) {
    return res.status(400).json({ error: "Titel und Code dürfen nicht leer sein." });
  }
  const stmt = db.prepare('INSERT INTO scripts (title, code, author) VALUES (?, ?, ?)');
  stmt.run(title, code, author || 'Anonym');
  res.json({ message: "Skript erfolgreich hochgeladen!" });
});

// 4. Alle Skripte abrufen
app.get('/api/scripts', (req, res) => {
  const stmt = db.prepare('SELECT * FROM scripts ORDER BY id DESC');
  const scripts = stmt.all();
  res.json(scripts);
});

// Port-Dynamik für Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Backend läuft erfolgreich auf Port ${PORT}`);
});
