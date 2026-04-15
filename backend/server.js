require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cors()); // Configure this to only allow requests from your FE IP later
// PostgreSQL Connection Pool
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST, // Your DB EC2 Private IP
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: 5432,
});
// REGISTER ROUTE
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        // Password Hashing
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        // Parameterized queries PREVENT SQL INJECTION
        const result = await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
            [username, email, passwordHash]
        );
        res.status(201).json({ message: 'User registered successfully!', user: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: 'Username or email already exists.' });
        }
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});
// LOGIN ROUTE
app.post('/api/login', async (req, res) => {
    const { identifier, password } = req.body;
    try {
        // Parameterized query
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1 OR LOWER(email) = LOWER($1)',
            [identifier]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const user = result.rows[0];
        
        // Verify Password
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        // In a real app, you'd generate a JWT token here. For M2, we return success.
        res.status(200).json({ message: 'Login successful!', username: user.username });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Backend Server running on port ${PORT}`);
});