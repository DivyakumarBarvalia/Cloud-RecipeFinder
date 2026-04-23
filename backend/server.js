require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
app.use(express.json());

const SESSION_COOKIE_NAME = 'session_id';
const SESSION_TTL_MS = 1000 * 60 * 60 * 8; // 8 hours
const sessions = new Map();
const frontendOrigin = process.env.FRONTEND_ORIGIN || true;
const SPOONACULAR_API_BASE = 'https://api.spoonacular.com';
const SPOONACULAR_API_KEY = process.env.SPOONACULAR_API_KEY;

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

function normalizeRole(role) {
    if (role === 'admin') {
        return 'admin';
    }
    return 'user';
}

async function getUserById(userId) {
    const result = await pool.query(
        'SELECT id, username, email, COALESCE(role, $2) AS role FROM users WHERE id = $1',
        [userId, 'user']
    );
    return result.rows[0] || null;
}

async function requireAuth(req, res, next) {
    const session = getSession(req);
    if (!session) {
        return res.status(401).json({ error: 'Authentication required.' });
    }

    try {
        const user = await getUserById(session.userId);
        if (!user) {
            return res.status(401).json({ error: 'Authentication required.' });
        }
        req.user = {
            id: user.id,
            username: user.username,
            email: user.email,
            role: normalizeRole(user.role)
        };
        return next();
    } catch (error) {
        return res.status(500).json({ error: 'Failed to validate session.' });
    }
}

function spoonacularUrl(path, searchParams = {}) {
    const url = new URL(`${SPOONACULAR_API_BASE}${path}`);
    Object.entries(searchParams).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
            url.searchParams.set(key, String(value));
        }
    });
    url.searchParams.set('apiKey', SPOONACULAR_API_KEY || '');
    return url.toString();
}

async function fetchSpoonacular(path, params = {}) {
    if (!SPOONACULAR_API_KEY) {
        return {
            ok: false,
            status: 500,
            error: 'SPOONACULAR_API_KEY is missing on the server.'
        };
    }

    const response = await fetch(spoonacularUrl(path, params));
    let data = null;
    try {
        data = await response.json();
    } catch (error) {
        data = null;
    }

    if (!response.ok) {
        const apiMessage = data && data.message ? data.message : 'Failed to fetch data from Spoonacular.';
        return {
            ok: false,
            status: response.status,
            error: apiMessage
        };
    }

    return { ok: true, data };
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

    // ✅ Keep validation
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Username, email and password are required.' });
    }

    try {
        // ✅ 1. Hash password (same as before)
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // ✅ 2. Generate MFA secret
        const secret = speakeasy.generateSecret({
            name: `CloudRecipeFinder (${username})`
        });

        // ✅ 3. Insert user with MFA secret (UPDATED query)
        const result = await pool.query(
            `INSERT INTO users (username, email, password_hash, role, mfa_secret)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, username, email, role`,
            [username, email, passwordHash, 'user', secret.base32]
        );

        // ✅ 4. Generate QR code
        const qrDataURL = await qrcode.toDataURL(secret.otpauth_url);

        // ✅ 5. Return BOTH user + QR
        res.status(201).json({
            message: 'User registered successfully!',
            user: result.rows[0],
            qrCode: qrDataURL
        });

    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: 'Username or email already exists.' });
        }
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/login', async (req, res) => {
    const { identifier, password, mfaCode } = req.body;

    if (!identifier || !password || !mfaCode) {
        return res.status(400).json({ error: 'Identifier, password, and MFA code are required.' });
    }

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1 OR LOWER(email) = LOWER($1)',
            [identifier]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];

        // 1. Verify password
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // 2. Enforce MFA (no conditional)
        if (!user.mfa_secret) {
            return res.status(500).json({ error: 'MFA not set up for this account.' });
        }

        const isVerified = speakeasy.totp.verify({
            secret: user.mfa_secret,
            encoding: 'base32',
            token: mfaCode,
            window: 1
        });

        if (!isVerified) {
            return res.status(401).json({ error: 'Invalid 6-digit MFA code.' });
        }

        // 3. Create session
        const sessionId = createSession(user);
        setSessionCookie(res, sessionId);

        res.status(200).json({
            message: 'Login successful!',
            username: user.username,
            role: normalizeRole(user.role)
        });

    } catch (err) {
        console.error(err);
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
        username: session.username,
        userId: session.userId
    });
});

app.get('/api/me', requireAuth, async (req, res) => {
    res.status(200).json({
        id: req.user.id,
        username: req.user.username,
        email: req.user.email,
        role: req.user.role
    });
});

app.get('/api/recipes/search', async (req, res) => {
    const ingredients = (req.query.ingredients || '').trim();
    const number = Math.min(parseInt(req.query.number, 10) || 12, 24);

    if (!ingredients) {
        return res.status(400).json({ error: 'Please provide ingredients.' });
    }

    try {
        const result = await fetchSpoonacular('/recipes/findByIngredients', {
            ingredients,
            number,
            ranking: 1,
            ignorePantry: true
        });

        if (!result.ok) {
            return res.status(result.status).json({ error: result.error });
        }

        return res.status(200).json({ recipes: result.data });
    } catch (error) {
        return res.status(500).json({ error: 'Unable to search recipes.' });
    }
});

app.get('/api/recipes/:recipeId', async (req, res) => {
    const recipeId = Number(req.params.recipeId);
    if (!Number.isFinite(recipeId)) {
        return res.status(400).json({ error: 'Invalid recipe id.' });
    }

    try {
        const [infoResult, nutritionResult] = await Promise.all([
            fetchSpoonacular(`/recipes/${recipeId}/information`, {
                includeNutrition: false
            }),
            fetchSpoonacular(`/recipes/${recipeId}/nutritionWidget.json`)
        ]);

        if (!infoResult.ok) {
            return res.status(infoResult.status).json({ error: infoResult.error });
        }

        const nutrition = nutritionResult.ok ? nutritionResult.data : null;
        return res.status(200).json({
            recipe: infoResult.data,
            nutrition
        });
    } catch (error) {
        return res.status(500).json({ error: 'Unable to load recipe details.' });
    }
});

app.get('/api/favorites', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT recipe_id, recipe_title, recipe_image, created_at
             FROM favorite_recipes
             WHERE user_id = $1
             ORDER BY created_at DESC`,
            [req.user.id]
        );
        return res.status(200).json({ favorites: result.rows });
    } catch (error) {
        return res.status(500).json({ error: 'Unable to fetch favorites.' });
    }
});

app.post('/api/favorites', requireAuth, async (req, res) => {
    const { recipeId, recipeTitle, recipeImage } = req.body;
    if (!recipeId || !recipeTitle) {
        return res.status(400).json({ error: 'recipeId and recipeTitle are required.' });
    }

    try {
        await pool.query(
            `INSERT INTO favorite_recipes (user_id, recipe_id, recipe_title, recipe_image)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id, recipe_id) DO NOTHING`,
            [req.user.id, recipeId, recipeTitle, recipeImage || null]
        );
        return res.status(201).json({ message: 'Recipe saved to favorites.' });
    } catch (error) {
        return res.status(500).json({ error: 'Unable to save favorite.' });
    }
});

app.delete('/api/favorites/:recipeId', requireAuth, async (req, res) => {
    const recipeId = Number(req.params.recipeId);
    if (!Number.isFinite(recipeId)) {
        return res.status(400).json({ error: 'Invalid recipe id.' });
    }

    try {
        await pool.query(
            'DELETE FROM favorite_recipes WHERE user_id = $1 AND recipe_id = $2',
            [req.user.id, recipeId]
        );
        return res.status(200).json({ message: 'Favorite removed.' });
    } catch (error) {
        return res.status(500).json({ error: 'Unable to remove favorite.' });
    }
});

app.get('/api/recipes/:recipeId/comments', async (req, res) => {
    const recipeId = Number(req.params.recipeId);
    if (!Number.isFinite(recipeId)) {
        return res.status(400).json({ error: 'Invalid recipe id.' });
    }

    try {
        const result = await pool.query(
            `SELECT id, recipe_id, user_id, username, comment_text, rating, created_at
             FROM recipe_comments
             WHERE recipe_id = $1
             ORDER BY created_at DESC`,
            [recipeId]
        );
        return res.status(200).json({ comments: result.rows });
    } catch (error) {
        return res.status(500).json({ error: 'Unable to fetch comments.' });
    }
});

app.post('/api/recipes/:recipeId/comments', requireAuth, async (req, res) => {
    const recipeId = Number(req.params.recipeId);
    const commentText = (req.body.commentText || '').trim();
    const rating = Number(req.body.rating);

    if (!Number.isFinite(recipeId)) {
        return res.status(400).json({ error: 'Invalid recipe id.' });
    }
    if (!commentText) {
        return res.status(400).json({ error: 'Comment text is required.' });
    }
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
        return res.status(400).json({ error: 'Rating must be an integer from 1 to 5.' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO recipe_comments (recipe_id, user_id, username, comment_text, rating)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, recipe_id, user_id, username, comment_text, rating, created_at`,
            [recipeId, req.user.id, req.user.username, commentText, rating]
        );
        return res.status(201).json({ comment: result.rows[0] });
    } catch (error) {
        return res.status(500).json({ error: 'Unable to post comment.' });
    }
});

app.put('/api/comments/:commentId', requireAuth, async (req, res) => {
    const commentId = Number(req.params.commentId);
    const commentText = (req.body.commentText || '').trim();
    const rating = Number(req.body.rating);

    if (!Number.isFinite(commentId)) {
        return res.status(400).json({ error: 'Invalid comment id.' });
    }
    if (!commentText) {
        return res.status(400).json({ error: 'Comment text is required.' });
    }
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
        return res.status(400).json({ error: 'Rating must be an integer from 1 to 5.' });
    }

    try {
        const existing = await pool.query(
            'SELECT user_id FROM recipe_comments WHERE id = $1',
            [commentId]
        );
        if (existing.rows.length === 0) {
            return res.status(404).json({ error: 'Comment not found.' });
        }

        const ownerId = existing.rows[0].user_id;
        if (req.user.role !== 'admin' && req.user.id !== ownerId) {
            return res.status(403).json({ error: 'You do not have permission to edit this comment.' });
        }

        const result = await pool.query(
            `UPDATE recipe_comments
             SET comment_text = $1, rating = $2
             WHERE id = $3
             RETURNING id, recipe_id, user_id, username, comment_text, rating, created_at`,
            [commentText, rating, commentId]
        );
        return res.status(200).json({ comment: result.rows[0] });
    } catch (error) {
        return res.status(500).json({ error: 'Unable to update comment.' });
    }
});

app.delete('/api/comments/:commentId', requireAuth, async (req, res) => {
    const commentId = Number(req.params.commentId);
    if (!Number.isFinite(commentId)) {
        return res.status(400).json({ error: 'Invalid comment id.' });
    }

    try {
        const existing = await pool.query(
            'SELECT user_id FROM recipe_comments WHERE id = $1',
            [commentId]
        );
        if (existing.rows.length === 0) {
            return res.status(404).json({ error: 'Comment not found.' });
        }

        const ownerId = existing.rows[0].user_id;
        if (req.user.role !== 'admin' && req.user.id !== ownerId) {
            return res.status(403).json({ error: 'You do not have permission to delete this comment.' });
        }

        await pool.query('DELETE FROM recipe_comments WHERE id = $1', [commentId]);
        return res.status(200).json({ message: 'Comment deleted.' });
    } catch (error) {
        return res.status(500).json({ error: 'Unable to delete comment.' });
    }
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