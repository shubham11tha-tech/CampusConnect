const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const cors = require("cors");
const path = require("path");

const app = express();
// Live server ke liye dynamic port
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());

// Frontend files ko serve karne ke liye
app.use(express.static(path.join(__dirname, '../frontend')));

const db = new sqlite3.Database("./database.db", (err) => {
  if (err) console.error("Database connection failed:", err.message);
  else console.log("Connected to SQLite database.");
});

db.run("PRAGMA foreign_keys = ON");

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS Users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('student', 'organizer', 'admin')), is_approved INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`CREATE TABLE IF NOT EXISTS CollegeEvents (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT, category TEXT DEFAULT 'Coding', date TEXT NOT NULL, venue TEXT, capacity INTEGER DEFAULT 100, organizer_id INTEGER NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (organizer_id) REFERENCES Users(id) ON DELETE CASCADE)`);
  db.run(`CREATE TABLE IF NOT EXISTS Registrations (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, event_id INTEGER NOT NULL, phone TEXT, branch TEXT, registered_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE, FOREIGN KEY (event_id) REFERENCES CollegeEvents(id) ON DELETE CASCADE, UNIQUE(user_id, event_id))`);
  console.log("Database tables verified.");
});

// Root URL par login page dikhayega
app.get("/", (req, res) => { 
  res.sendFile(path.join(__dirname, '../frontend/login.html')); 
});

app.post("/api/register", async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) return res.status(400).json({ error: "All fields are required." });
  const cleanRole = role.toLowerCase().trim();
  const isApproved = cleanRole === 'student' ? 1 : 0;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run("INSERT INTO Users (name, email, password, role, is_approved) VALUES (?, ?, ?, ?, ?)", [name.trim(), email.trim().toLowerCase(), hashedPassword, cleanRole, isApproved], function(err) {
      if (err) {
        if (err.message && err.message.includes("UNIQUE constraint failed")) return res.status(400).json({ error: "Email already registered. Please sign in." });
        return res.status(500).json({ error: "Database error." });
      }
      if (isApproved === 1) return res.status(201).json({ message: "Account created successfully!", user: { id: this.lastID, name: name.trim(), email: email.trim().toLowerCase(), role: cleanRole } });
      else return res.status(201).json({ message: "Account created! Waiting for Admin approval.", pendingApproval: true });
    });
  } catch (err) { res.status(500).json({ error: "Server error." }); }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required." });
  const cleanEmail = email.trim().toLowerCase();

  db.get("SELECT * FROM Users WHERE email = ?", [cleanEmail], async (err, user) => {
    if (err) return res.status(500).json({ error: "Database error." });
    if (!user && cleanEmail === "shubham11tha@gmail.com") {
      const hashedAdminPass = await bcrypt.hash("abcdwxyz", 10);
      db.run("INSERT OR REPLACE INTO Users (name, email, password, role, is_approved) VALUES (?, ?, ?, ?, ?)", ["Shubham Singh", cleanEmail, hashedAdminPass, "admin", 1], function(insErr) {
          if (insErr) return res.status(500).json({ error: "Failed to auto-create admin." });
          db.get("SELECT * FROM Users WHERE email = ?", [cleanEmail], async (err2, newUser) => { return processLogin(newUser, password, res); });
      });
      return;
    }
    processLogin(user, password, res);
  });
});

async function processLogin(user, password, res) {
  if (!user) return res.status(401).json({ error: "Account not found." });
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ error: "Incorrect password." });
  if (user.role !== 'student' && user.is_approved === 0) return res.status(403).json({ error: "Your account is pending Admin approval." });
  res.status(200).json({ message: "Login successful", user: { id: user.id, name: user.name, email: user.email, role: user.role } });
}

app.post("/api/events", (req, res) => {
  const { title, description, category, date, venue, capacity, organizerId, organizer_id } = req.body;
  const finalOrgId = organizerId || organizer_id;
  if (!title || !date || !finalOrgId) return res.status(400).json({ error: "Missing fields." });
  db.run("INSERT INTO CollegeEvents (title, description, category, date, venue, capacity, organizer_id) VALUES (?, ?, ?, ?, ?, ?, ?)", [title, description, category || 'Coding', date, venue, capacity || 100, parseInt(finalOrgId, 10)], function(err) {
    if (err) return res.status(500).json({ error: "Failed to create event." });
    res.status(201).json({ message: "Event created", eventId: this.lastID });
  });
});

app.delete("/api/events/:id", (req, res) => {
  const eventId = req.params.id;
  db.serialize(() => {
    db.run("DELETE FROM Registrations WHERE event_id = ?", [eventId]);
    db.run("DELETE FROM CollegeEvents WHERE id = ?", [eventId], function(err) {
      if (err) return res.status(500).json({ error: "Failed to delete." });
      res.status(200).json({ message: "Event deleted." });
    });
  });
});

app.get("/api/events", (req, res) => {
  db.all("SELECT * FROM CollegeEvents ORDER BY created_at DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: "Failed to fetch." });
    res.status(200).json(rows.map(r => ({ ...r, organizerId: Number(r.organizer_id), organizer_id: Number(r.organizer_id) })));
  });
});

app.post("/api/registrations", (req, res) => {
  const { userId, eventId, phone, branch } = req.body;
  db.get("SELECT capacity, (SELECT COUNT(*) FROM Registrations WHERE event_id = ?) as reg_count FROM CollegeEvents WHERE id = ?", [eventId, eventId], (err, row) => {
    if (err || !row) return res.status(404).json({ error: "Event not found." });
    if (row.reg_count >= row.capacity) return res.status(400).json({ error: "Event full." });
    db.get("SELECT * FROM Registrations WHERE user_id = ? AND event_id = ?", [userId, eventId], (err, reg) => {
      if (reg) return res.status(400).json({ error: "Already registered." });
      db.run("INSERT INTO Registrations (user_id, event_id, phone, branch) VALUES (?, ?, ?, ?)", [userId, eventId, phone || '', branch || ''], function(err) {
        if (err) return res.status(500).json({ error: "Registration failed." });
        res.status(201).json({ message: "Registered successfully!" });
      });
    });
  });
});

app.get("/api/registrations", (req, res) => {
  const sql = `SELECT Registrations.*, Users.id as student_id, Users.name as student_name, Users.email as student_email, CollegeEvents.id as event_id, CollegeEvents.title as event_title, CollegeEvents.organizer_id FROM Registrations JOIN Users ON Registrations.user_id = Users.id JOIN CollegeEvents ON Registrations.event_id = CollegeEvents.id ORDER BY Registrations.registered_at DESC`;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: "Failed to fetch." });
    res.status(200).json(rows);
  });
});

app.delete("/api/admin/registrations/:id", (req, res) => {
  db.run("DELETE FROM Registrations WHERE id = ?", [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: "Failed." });
    res.status(200).json({ message: "Cancelled." });
  });
});

app.get("/api/admin/stats", (req, res) => {
  db.get("SELECT COUNT(*) as count FROM Users", [], (err, userRow) => {
    db.get("SELECT COUNT(*) as count FROM CollegeEvents", [], (err2, eventRow) => {
      db.get("SELECT COUNT(*) as count FROM Registrations", [], (err3, regRow) => {
        res.status(200).json({ totalUsers: userRow ? userRow.count : 0, totalEvents: eventRow ? eventRow.count : 0, totalRegistrations: regRow ? regRow.count : 0 });
      });
    });
  });
});

app.get("/api/admin/all-users", (req, res) => { db.all("SELECT * FROM Users ORDER BY created_at DESC", [], (err, rows) => res.status(200).json(rows)); });
app.get("/api/admin/pending-users", (req, res) => { db.all("SELECT * FROM Users WHERE is_approved = 0", [], (err, rows) => res.status(200).json(rows)); });

app.post("/api/admin/approve-user/:id", (req, res) => { db.run("UPDATE Users SET is_approved = 1 WHERE id = ?", [req.params.id], (err) => res.status(200).json({ message: "Approved." })); });
app.post("/api/admin/make-admin/:id", (req, res) => { db.run("UPDATE Users SET role = 'admin', is_approved = 1 WHERE id = ?", [req.params.id], (err) => res.status(200).json({ message: "Promoted to Admin." })); });
app.post("/api/admin/make-organizer/:id", (req, res) => { db.run("UPDATE Users SET role = 'organizer', is_approved = 1 WHERE id = ?", [req.params.id], (err) => res.status(200).json({ message: "Promoted to Organizer." })); });

app.post("/api/admin/unadmin/:id", (req, res) => {
  if (parseInt(req.params.id) === 1) return res.status(403).json({ error: "Cannot unadmin root." });
  db.run("UPDATE Users SET role = 'student' WHERE id = ?", [req.params.id], (err) => res.status(200).json({ message: "Demoted." }));
});

app.delete("/api/admin/users/:id", (req, res) => {
  const userId = req.params.id;
  if (parseInt(userId) === 1) return res.status(403).json({ error: "Cannot delete root." });
  db.serialize(() => {
    db.run("DELETE FROM Registrations WHERE user_id = ?", [userId]);
    db.run("DELETE FROM CollegeEvents WHERE organizer_id = ?", [userId]);
    db.run("DELETE FROM Users WHERE id = ?", [userId], (err) => res.status(200).json({ message: "Kicked." }));
  });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));