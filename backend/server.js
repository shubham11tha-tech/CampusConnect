const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../frontend')));

// PostgreSQL Cloud Database Connection (Neon)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Initialize Database Tables with is_approved column
async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS Users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'student',
                is_approved INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS CollegeEvents (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                date TEXT NOT NULL,
                venue TEXT,
                capacity INTEGER,
                organizer_id INTEGER REFERENCES Users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS Registrations (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES Users(id) ON DELETE CASCADE,
                event_id INTEGER REFERENCES CollegeEvents(id) ON DELETE CASCADE,
                UNIQUE(user_id, event_id)
            );
        `);
        console.log("Database & Tables initialized successfully.");
    } catch (err) {
        console.error("Database initialization error:", err);
    }
}
initDB();

// --- AUTHENTICATION ROUTES ---

// Register
app.post('/api/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Organizers require admin approval (is_approved = 0), others approved by default (1)
        const isApproved = (role === 'organizer') ? 0 : 1;

        const newUserData = await pool.query(
            `INSERT INTO Users (name, email, password, role, is_approved) 
             VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, role, is_approved`,
            [name, email, hashedPassword, role || 'student', isApproved]
        );
        res.status(201).json(newUserData.rows[0]);
    } catch (err) {
        res.status(400).json({ error: "Email already registered or invalid data." });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const userResult = await pool.query('SELECT * FROM Users WHERE email = $1', [email]);
        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: "Invalid email or password." });
        }
        
        const user = userResult.rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ error: "Invalid email or password." });
        }

        // Check if organizer is approved
        if (user.role === 'organizer' && user.is_approved === 0) {
            return res.status(403).json({ error: "Your account is pending Admin approval." });
        }

        res.json({ id: user.id, name: user.name, email: user.email, role: user.role });
    } catch (err) {
        res.status(500).json({ error: "Server error during login." });
    }
});

// --- ADMIN ROUTES ---

// Get Stats
app.get('/api/admin/stats', async (req, res) => {
    try {
        const usersCount = await pool.query('SELECT COUNT(*) FROM Users');
        const eventsCount = await pool.query('SELECT COUNT(*) FROM CollegeEvents');
        const regCount = await pool.query('SELECT COUNT(*) FROM Registrations');
        
        res.json({
            totalUsers: parseInt(usersCount.rows[0].count),
            totalEvents: parseInt(eventsCount.rows[0].count),
            totalRegistrations: parseInt(regCount.rows[0].count)
        });
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch stats." });
    }
});

// Get All Users
app.get('/api/admin/all-users', async (req, res) => {
    try {
        const users = await pool.query('SELECT id, name, email, role, is_approved FROM Users ORDER BY id ASC');
        res.json(users.rows);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch users." });
    }
});

// Approve User
app.post('/api/admin/approve-user/:id', async (req, res) => {
    try {
        await pool.query('UPDATE Users SET is_approved = 1 WHERE id = $1', [req.params.id]);
        res.json({ message: "User approved successfully." });
    } catch (err) {
        res.status(500).json({ error: "Failed to approve user." });
    }
});

// Promote Role (Make Admin / Make Organizer)
app.post('/api/admin/make-admin/:id', async (req, res) => {
    try {
        await pool.query("UPDATE Users SET role = 'admin', is_approved = 1 WHERE id = $1", [req.params.id]);
        res.json({ message: "User promoted to admin." });
    } catch (err) { res.status(500).json({ error: "Failed." }); }
});

app.post('/api/admin/make-organizer/:id', async (req, res) => {
    try {
        await pool.query("UPDATE Users SET role = 'organizer', is_approved = 1 WHERE id = $1", [req.params.id]);
        res.json({ message: "User promoted to organizer." });
    } catch (err) { res.status(500).json({ error: "Failed." }); }
});

// Demote to Student (Unadmin / Remove Org)
app.post('/api/admin/unadmin/:id', async (req, res) => {
    try {
        const targetUser = await pool.query("SELECT email FROM Users WHERE id = $1", [req.params.id]);
        // Strict protection for main root email only
        if (targetUser.rows[0]?.email === 'shubham11tha@gmail.com') {
            return res.status(403).json({ error: "Cannot modify root admin permissions." });
        }
        await pool.query("UPDATE Users SET role = 'student' WHERE id = $1", [req.params.id]);
        res.json({ message: "User demoted to student." });
    } catch (err) { res.status(500).json({ error: "Failed." }); }
});

// Delete/Kick User
app.delete('/api/admin/users/:id', async (req, res) => {
    try {
        const targetUser = await pool.query("SELECT email FROM Users WHERE id = $1", [req.params.id]);
        if (targetUser.rows[0]?.email === 'shubham11tha@gmail.com') {
            return res.status(403).json({ error: "Cannot delete root admin." });
        }
        await pool.query('DELETE FROM Users WHERE id = $1', [req.params.id]);
        res.json({ message: "User kicked." });
    } catch (err) { res.status(500).json({ error: "Failed." }); }
});

// --- EVENT ROUTES ---

app.get('/api/events', async (req, res) => {
    try {
        const events = await pool.query('SELECT * FROM CollegeEvents ORDER BY id DESC');
        res.json(events.rows);
    } catch (err) { res.status(500).json({ error: "Failed to fetch events." }); }
});

app.post('/api/events', async (req, res) => {
    const { title, description, date, venue, capacity, organizer_id } = req.body;
    try {
        const newEvent = await pool.query(
            `INSERT INTO CollegeEvents (title, description, date, venue, capacity, organizer_id) 
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
            [title, description, date, venue, capacity, organizer_id]
        );
        res.status(201).json(newEvent.rows[0]);
    } catch (err) { res.status(400).json({ error: "Failed to create event." }); }
});

app.delete('/api/events/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM CollegeEvents WHERE id = $1', [req.params.id]);
        res.json({ message: "Event deleted." });
    } catch (err) { res.status(500).json({ error: "Failed." }); }
});

// --- REGISTRATION / TICKETING ROUTES ---

app.get('/api/registrations', async (req, res) => {
    try {
        const regs = await pool.query('SELECT * FROM Registrations');
        res.json(regs.rows);
    } catch (err) { res.status(500).json({ error: "Failed." }); }
});

app.post('/api/registrations', async (req, res) => {
    const { userId, eventId } = req.body;
    try {
        const existing = await pool.query('SELECT * FROM Registrations WHERE user_id = $1 AND event_id = $2', [userId, eventId]);
        if (existing.rows.length > 0) {
            return res.status(400).json({ error: "Already registered for this event." });
        }
        await pool.query('INSERT INTO Registrations (user_id, event_id) VALUES ($1, $2)', [userId, eventId]);
        res.status(201).json({ message: "Registered successfully." });
    } catch (err) { res.status(500).json({ error: "Registration failed." }); }
});

// Fallback to frontend index.html
// Fallback to frontend index.html
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});