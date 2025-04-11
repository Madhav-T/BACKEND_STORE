// backend/server.js
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');

const app = express();
const db = new sqlite3.Database(':memory:'); // Use a file for persistent storage

app.use(cors());
app.use(bodyParser.json());

// Initialize database tables
db.serialize(() => {
    db.run(`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT, address TEXT, role TEXT)`);
    db.run(`CREATE TABLE stores (id INTEGER PRIMARY KEY, name TEXT, email TEXT, address TEXT, rating REAL)`);
    db.run(`CREATE TABLE ratings (id INTEGER PRIMARY KEY, user_id INTEGER, store_id INTEGER, rating INTEGER)`);
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).send("No token provided.");

    jwt.verify(token.split(' ')[1], 'secret', (err, decoded) => {
        if (err) return res.status(500).send("Failed to authenticate token.");
        req.userId = decoded.id;
        req.userRole = decoded.role;
        next();
    });
};

// User registration
app.post('/api/register', [
    body('name').isLength({ min: 20, max: 60 }),
    body('email').isEmail(),
    body('password').isLength({ min: 8, max: 16 }).matches(/[A-Z]/).matches(/[!@#$%^&*]/),
    body('address').isLength({ max: 400 })
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { name, email, password, address } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);
    db.run(`INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, 'normal')`, [name, email, hashedPassword, address], function(err) {
        if (err) return res.status(500).send("Error registering user.");
        res.status(201).send({ id: this.lastID });
    });
});

// User login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err || !user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).send("Invalid credentials.");
        }
        const token = jwt.sign({ id: user.id, role: user.role }, 'secret', { expiresIn: 86400 });
        res.status(200).send({ auth: true, token });
    });
});

// Get all stores
app.get('/api/stores', verifyToken, (req, res) => {
    db.all(`SELECT * FROM stores`, [], (err, stores) => {
        if (err) return res.status(500).send(err);
        res.json(stores);
    });
});

// Rate a store
app.post('/api/rate', verifyToken, (req, res) => {
    const { storeId, rating } = req.body;
    db.run(`INSERT INTO ratings (user_id, store_id, rating) VALUES (?, ?, ?)`, [req.userId, storeId, rating], function(err) {
        if (err) return res.status(500).send("Error submitting rating.");
        res.status(201).send({ id: this.lastID });
    });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});