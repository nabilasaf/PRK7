require('dotenv').config(); // Memuat variabel dari .env

const express = require('express');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const cors = require('cors'); 
const app = express();

// --- KONFIGURASI DARI .ENV ---
const port = process.env.PORT || 3000;
const API_PREFIX = '/api';

const dbConfig = {
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE,
};

// Middleware
app.use(cors()); 
app.use(express.json()); 

// Global Connection Pool
let pool;
try {
    pool = mysql.createPool(dbConfig);
    console.log("MySQL Pool berhasil dibuat.");
} catch (error) {
    console.error("Gagal membuat MySQL Pool. Cek file .env dan kredensial database:", error.message);
    process.exit(1); 
}

// --- FUNGSI UTILITAS ---

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function generateApiKey() {
    return crypto.randomBytes(32).toString('hex');
}

function getExpirationDate(days = 30) {
    const date = new Date();
    date.setDate(date.getDate() + days);
    return date.toISOString().slice(0, 19).replace('T', ' '); // Format MySQL DATETIME
}

// --- MIDDLEWARE AUTENTIKASI ADMIN SEMENTARA ---
const ADMIN_TOKEN_DUMMY = process.env.API_DUMMY_TOKEN; 

function adminAuthMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Autentikasi diperlukan.' });
    }
    const token = authHeader.split(' ')[1];
    if (token === ADMIN_TOKEN_DUMMY) {
        next();
    } else {
        res.status(403).json({ message: 'Token admin tidak valid.' });
    }
}

// =========================================================
// 1. ENDPOINTS ADMIN
// =========================================================

// POST /api/admin/register
app.post(`${API_PREFIX}/admin/register`, async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email dan password diperlukan.' });
    }
    try {
        const password_hash = hashPassword(password);
        await pool.query(
            'INSERT INTO admins (email, password_hash) VALUES (?, ?)',
            [email, password_hash]
        );
        res.status(201).json({ message: 'Admin berhasil didaftarkan.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Email admin sudah terdaftar.' });
        }
        console.error("Error registrasi admin:", error);
        res.status(500).json({ message: 'Gagal mendaftarkan admin.' });
    }
});

// POST /api/admin/login
app.post(`${API_PREFIX}/admin/login`, async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email dan password diperlukan.' });
    }
    try {
        const [rows] = await pool.query(
            'SELECT password_hash FROM admins WHERE email = ?',
            [email]
        );
        if (rows.length === 0) {
            return res.status(401).json({ message: 'Email atau password salah.' });
        }
        const admin = rows[0];
        const inputHash = hashPassword(password);
        if (inputHash === admin.password_hash) {
            res.status(200).json({ message: 'Login berhasil.', token: ADMIN_TOKEN_DUMMY });
        } else {
            res.status(401).json({ message: 'Email atau password salah.' });
        }
    } catch (error) {
        console.error("Error login admin:", error);
        res.status(500).json({ message: 'Gagal login.' });
    }
});

// GET /api/admin/dashboard
app.get(`${API_PREFIX}/admin/dashboard`, adminAuthMiddleware, async (req, res) => {
    try {
        const [users] = await pool.query('SELECT id, first_name, last_name, email FROM users ORDER BY created_at DESC');
        const [keys] = await pool.query('SELECT id, user_id, api_key, expires_at FROM api_keys ORDER BY created_at DESC');
        res.status(200).json({ users, keys });
    } catch (error) {
        console.error("Error mengambil data dasbor:", error);
        res.status(500).json({ message: 'Gagal mengambil data dasbor.' });
    }
});

// =========================================================
// 2. ENDPOINTS PENGGUNA
// =========================================================

// POST /api/user/register
app.post(`${API_PREFIX}/user/register`, async (req, res) => {
    const { first_name, last_name, email } = req.body;
    if (!first_name || !last_name || !email) {
        return res.status(400).json({ message: 'Nama depan, nama belakang, dan email diperlukan.' });
    }
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();
        
        const [userResult] = await connection.query(
            'INSERT INTO users (first_name, last_name, email) VALUES (?, ?, ?)',
            [first_name, last_name, email]
        );
        const newUserId = userResult.insertId;
        
        const apiKey = generateApiKey();
        const expiresAt = getExpirationDate(30); 
        
        await connection.query(
            'INSERT INTO api_keys (user_id, api_key, expires_at) VALUES (?, ?, ?)',
            [newUserId, apiKey, expiresAt]
        );
        
        await connection.commit();
        
        res.status(201).json({ 
            message: 'Registrasi berhasil. API Key dibuat.',
            apiKey: apiKey,
            expiresAt: expiresAt 
        });
    } catch (error) {
        if (connection) await connection.rollback();
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Email pengguna sudah terdaftar.' });
        }
        console.error("Error registrasi pengguna:", error);
        res.status(500).json({ message: 'Gagal registrasi pengguna.' });
    } finally {
        if (connection) connection.release();
    }
});

// =========================================================
// SERVER START
// =========================================================
app.listen(port, () => {
    console.log(`Backend API berjalan di http://localhost:${port}`);
    console.log(`API Prefix: ${API_PREFIX}`);
    console.log(`Kredensial database dimuat dari .env`);
});
