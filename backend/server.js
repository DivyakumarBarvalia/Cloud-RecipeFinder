require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
app.use(express.json());

const SESSION_COOKIE_NAME = 'session_id';
const SESSION_TTL_MS = 1000 * 60 * 60 * 8; // 8 hours
const sessions = new Map();
const frontendOrigin = process.env.FRONTEND_ORIGIN || true;

app.use(
    cors({
        origin: frontendOrigin,
        credentials: true
    })
);

function parseCookies(req) {
    const rawCookie = req.headers.cookie;
    if (!rawCookie) {
        return {};
    }

    return rawCookie.split(';').reduce((acc, pair) => {
        const separatorIndex = pair.indexOf('=');
        if (separatorIndex === -1) {
            return acc;
        }

        const key = pair.slice(0, separatorIndex).trim();
        const value = decodeURIComponent(pair.slice(separatorIndex + 1).trim());
        acc[key] = value;
        return acc;
    }, {});
}

function createSession(user) {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    sessions.set(sessionId, {
        userId: user.id,
        username: user.username,
        createdAt: now,
        expiresAt: now + SESSION_TTL_MS
    });
    return sessionId;
}

function getSession(req) {
    const cookies = parseCookies(req);
    const sessionId = cookies[SESSION_COOKIE_NAME];
    if (!sessionId) {
        return null;
    }

    const session = sessions.get(sessionId);
    if (!session) {
        return null;
    }

    if (session.expiresAt < Date.now()) {
        sessions.delete(sessionId);
        return null;
    }

    session.expiresAt = Date.now() + SESSION_TTL_MS;
    sessions.set(sessionId, session);
    return { sessionId, ...session };
}

function setSessionCookie(res, sessionId) {
    const isProduction = process.env.NODE_ENV === 'production';
    const cookieAttributes = [
        `${SESSION_COOKIE_NAME}=${encodeURIComponent(sessionId)}`,
        'HttpOnly',
        'Path=/',
        `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
        'SameSite=Lax'
    ];

    if (isProduction) {
        cookieAttributes.push('Secure');
    }

    res.setHeader('Set-Cookie', cookieAttributes.join('; '));
}

function clearSessionCookie(res) {
    res.setHeader(
        'Set-Cookie',
        `${SESSION_COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`
    );
}

setInterval(() => {
    const now = Date.now();
    for (const [sessionId, session] of sessions.entries()) {
        if (session.expiresAt < now) {
            sessions.delete(sessionId);
        }
    }
}, 1000 * 60 * 5);
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
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Username, email and password are required.' });
    }
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
    if (!identifier || !password) {
        return res.status(400).json({ error: 'Identifier and password are required.' });
    }

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
        const sessionId = createSession(user);
        setSessionCookie(res, sessionId);
        res.status(200).json({ message: 'Login successful!', username: user.username });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/session', (req, res) => {
    const session = getSession(req);
    if (!session) {
        return res.status(401).json({ authenticated: false });
    }

    res.status(200).json({
        authenticated: true,
        username: session.username
    });
});

app.get('/api/logged-in-users', (req, res) => {
    const activeUsers = new Set();
    for (const session of sessions.values()) {
        if (session.expiresAt >= Date.now()) {
            activeUsers.add(session.username);
        }
    }

    res.status(200).json({ users: Array.from(activeUsers) });
});

app.post('/api/logout', (req, res) => {
    const cookies = parseCookies(req);
    const sessionId = cookies[SESSION_COOKIE_NAME];
    if (sessionId) {
        sessions.delete(sessionId);
    }

    clearSessionCookie(res);
    res.status(200).json({ message: 'Signed out successfully.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Backend Server running on port ${PORT}`);
});