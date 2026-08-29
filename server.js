const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = "mein_geheimes_passwort_key";
let db;

// Datenbank initialisieren (Nutzt /tmp Ordner für Schreibrechte auf Render)
(async () => {
  try {
    db = await open({ 
      filename: '/tmp/database.sqlite', 
      driver: sqlite3.Database 
    });
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT);
      CREATE TABLE IF NOT EXISTS scripts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, code TEXT, author TEXT);
    `);
    console.log("Datenbank erfolgreich verbunden!");
  } catch (err) {
    console.error("Fehler bei der Datenbank-Initialisierung:", err);
  }
})();

// 1. Registrierung
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Benutzername und Passwort erforderlich." });
  }
  
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    await db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
    res.json({ message: "Account erfolgreich erstellt!" });
  } catch (e) {
    res.status(400).json({ error: "Benutzername bereits vergeben." });
  }
});

// 2. Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ username: user.username }, SECRET_KEY);
    res.json({ token, username: user.username });
  } else {
    res.status(400).json({ error: "Ungültige Anmeldedaten." });
  }
});

// 3. Skript hochladen
app.post('/api/scripts', async (req, res) => {
  const { title, code, author } = req.body;
  if (!title || !code) {
    return res.status(400).json({ error: "Titel und Code dürfen nicht leer sein." });
  }
  await db.run('INSERT INTO scripts (title, code, author) VALUES (?, ?, ?)', [title, code, author || 'Anonym']);
  res.json({ message: "Skript erfolgreich hochgeladen!" });
});

// 4. Alle Skripte abrufen
app.get('/api/scripts', async (req, res) => {
  const scripts = await db.all('SELECT * FROM scripts ORDER BY id DESC');
  res.json(scripts);
});

// Port-Dynamik für Render (Nutzt process.env.PORT)
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Backend läuft erfolgreich auf Port ${PORT}`);
});
