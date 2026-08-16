const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '../frontend')));

// Cloud Database (Neon) Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const initDB = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS Users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL CHECK(role IN ('student', 'organizer', 'admin')),
        is_approved INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS CollegeEvents (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        category VARCHAR(100) DEFAULT 'Coding',
        date VARCHAR(100) NOT NULL,
        venue VARCHAR(255),
        capacity INTEGER DEFAULT 100,
        organizer_id INTEGER NOT NULL REFERENCES Users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS Registrations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES Users(id) ON DELETE CASCADE,
        event_id INTEGER NOT NULL REFERENCES CollegeEvents(id) ON DELETE CASCADE,
        phone VARCHAR(50),
        branch VARCHAR(100),
        registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, event_id)
      );
    `);
    console.log("Cloud Database connected and verified.");
  } catch (err) {
    console.error("Database initialization error:", err);
  }
};

initDB();

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
    const result = await pool.query(
      "INSERT INTO Users (name, email, password, role, is_approved) VALUES ($1, $2, $3, $4, $5) RETURNING id",
      [name.trim(), email.trim().toLowerCase(), hashedPassword, cleanRole, isApproved]
    );
    const newUserId = result.rows[0].id;

    if (isApproved === 1) return res.status(201).json({ message: "Account created successfully!", user: { id: newUserId, name: name.trim(), email: email.trim().toLowerCase(), role: cleanRole } });
    else return res.status(201).json({ message: "Account created! Waiting for Admin approval.", pendingApproval: true });
    
  } catch (err) { 
    if (err.code === '23505') return res.status(400).json({ error: "Email already registered. Please sign in." });
    res.status(500).json({ error: "Server error." }); 
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required." });
  const cleanEmail = email.trim().toLowerCase();

  try {
      const userRes = await pool.query("SELECT * FROM Users WHERE email = $1", [cleanEmail]);
      let user = userRes.rows[0];

      if (!user && cleanEmail === "shubham11tha@gmail.com") {
          const hashedAdminPass = await bcrypt.hash("abcdwxyz", 10);
          const insertRes = await pool.query(
              "INSERT INTO Users (name, email, password, role, is_approved) VALUES ($1, $2, $3, $4, $5) RETURNING *",
              ["Shubham Singh", cleanEmail, hashedAdminPass, "admin", 1]
          );
          user = insertRes.rows[0];
      }

      if (!user) return res.status(401).json({ error: "Account not found." });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).json({ error: "Incorrect password." });
      if (user.role !== 'student' && user.is_approved === 0) return res.status(403).json({ error: "Your account is pending Admin approval." });

      res.status(200).json({ message: "Login successful", user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
      res.status(500).json({ error: "Database error." });
  }
});

app.post("/api/events", async (req, res) => {
  const { title, description, category, date, venue, capacity, organizerId, organizer_id } = req.body;
  const finalOrgId = organizerId || organizer_id;
  if (!title || !date || !finalOrgId) return res.status(400).json({ error: "Missing fields." });

  try {
      const result = await pool.query(
          "INSERT INTO CollegeEvents (title, description, category, date, venue, capacity, organizer_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
          [title, description, category || 'Coding', date, venue, capacity || 100, parseInt(finalOrgId, 10)]
      );
      res.status(201).json({ message: "Event created", eventId: result.rows[0].id });
  } catch (err) {
      res.status(500).json({ error: "Failed to create event." });
  }
});

app.delete("/api/events/:id", async (req, res) => {
  try {
      await pool.query("DELETE FROM CollegeEvents WHERE id = $1", [req.params.id]);
      res.status(200).json({ message: "Event deleted." });
  } catch (err) { res.status(500).json({ error: "Failed to delete." }); }
});

app.get("/api/events", async (req, res) => {
  try {
      const result = await pool.query("SELECT * FROM CollegeEvents ORDER BY created_at DESC");
      res.status(200).json(result.rows.map(r => ({ ...r, organizerId: Number(r.organizer_id), organizer_id: Number(r.organizer_id) })));
  } catch (err) { res.status(500).json({ error: "Failed to fetch." }); }
});

app.post("/api/registrations", async (req, res) => {
  const { userId, eventId, phone, branch } = req.body;
  try {
      const evRes = await pool.query("SELECT capacity, (SELECT COUNT(*) FROM Registrations WHERE event_id = $1) as reg_count FROM CollegeEvents WHERE id = $1", [eventId]);
      if (evRes.rows.length === 0) return res.status(404).json({ error: "Event not found." });

      const row = evRes.rows[0];
      if (Number(row.reg_count) >= row.capacity) return res.status(400).json({ error: "Event full." });

      await pool.query("INSERT INTO Registrations (user_id, event_id, phone, branch) VALUES ($1, $2, $3, $4)", [userId, eventId, phone || '', branch || '']);
      res.status(201).json({ message: "Registered successfully!" });
  } catch (err) {
      if (err.code === '23505') return res.status(400).json({ error: "Already registered." });
      res.status(500).json({ error: "Registration failed." });
  }
});

app.get("/api/registrations", async (req, res) => {
  const sql = `SELECT Registrations.*, Users.id as student_id, Users.name as student_name, Users.email as student_email, CollegeEvents.id as event_id, CollegeEvents.title as event_title, CollegeEvents.organizer_id FROM Registrations JOIN Users ON Registrations.user_id = Users.id JOIN CollegeEvents ON Registrations.event_id = CollegeEvents.id ORDER BY Registrations.registered_at DESC`;
  try {
      const result = await pool.query(sql);
      res.status(200).json(result.rows);
  } catch (err) { res.status(500).json({ error: "Failed to fetch." }); }
});

app.delete("/api/admin/registrations/:id", async (req, res) => {
  try {
      await pool.query("DELETE FROM Registrations WHERE id = $1", [req.params.id]);
      res.status(200).json({ message: "Cancelled." });
  } catch (err) { res.status(500).json({ error: "Failed." }); }
});

app.get("/api/admin/stats", async (req, res) => {
  try {
      const userRes = await pool.query("SELECT COUNT(*) as count FROM Users");
      const eventRes = await pool.query("SELECT COUNT(*) as count FROM CollegeEvents");
      const regRes = await pool.query("SELECT COUNT(*) as count FROM Registrations");
      res.status(200).json({
          totalUsers: parseInt(userRes.rows[0].count),
          totalEvents: parseInt(eventRes.rows[0].count),
          totalRegistrations: parseInt(regRes.rows[0].count)
      });
  } catch (err) { res.status(500).json({ error: "Failed to fetch stats." }); }
});

app.get("/api/admin/all-users", async (req, res) => {
  try {
      const result = await pool.query("SELECT * FROM Users ORDER BY created_at DESC");
      res.status(200).json(result.rows);
  } catch(err) { res.status(500).json({error: "Failed"}); }
});

app.get("/api/admin/pending-users", async (req, res) => {
  try {
      const result = await pool.query("SELECT * FROM Users WHERE is_approved = 0");
      res.status(200).json(result.rows);
  } catch(err) { res.status(500).json({error: "Failed"}); }
});

app.post("/api/admin/approve-user/:id", async (req, res) => {
  try {
      await pool.query("UPDATE Users SET is_approved = 1 WHERE id = $1", [req.params.id]);
      res.status(200).json({ message: "Approved." });
  } catch(err) { res.status(500).json({error:"Failed"});}
});

app.post("/api/admin/make-admin/:id", async (req, res) => {
  try {
      await pool.query("UPDATE Users SET role = 'admin', is_approved = 1 WHERE id = $1", [req.params.id]);
      res.status(200).json({ message: "Promoted to Admin." });
  } catch(err) { res.status(500).json({error:"Failed"});}
});

app.post("/api/admin/make-organizer/:id", async (req, res) => {
  try {
      await pool.query("UPDATE Users SET role = 'organizer', is_approved = 1 WHERE id = $1", [req.params.id]);
      res.status(200).json({ message: "Promoted to Organizer." });
  } catch(err) { res.status(500).json({error:"Failed"});}
});

app.post("/api/admin/unadmin/:id", async (req, res) => {
  if (parseInt(req.params.id) === 1) return res.status(403).json({ error: "Cannot unadmin root." });
  try {
      await pool.query("UPDATE Users SET role = 'student' WHERE id = $1", [req.params.id]);
      res.status(200).json({ message: "Demoted." });
  } catch(err) { res.status(500).json({error:"Failed"});}
});

app.delete("/api/admin/users/:id", async (req, res) => {
  const userId = req.params.id;
  if (parseInt(userId) === 1) return res.status(403).json({ error: "Cannot delete root." });
  try {
      await pool.query("DELETE FROM Users WHERE id = $1", [userId]);
      res.status(200).json({ message: "Kicked." });
  } catch(err) { res.status(500).json({error:"Failed"});}
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));