// backend/server.js
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const WebSocket = require('ws');

const app = express();
const db = new sqlite3.Database(':memory:'); // Use a file for persistent storage
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
const wss = new WebSocket.Server({ server });

app.use(cors());
app.use(bodyParser.json());

// Store connected clients
const clients = new Map();

wss.on('connection', ws => {
    const userId = generateUniqueId(); // You'll need a way to identify the user (e.g., from JWT or a query param)
    clients.set(ws, userId);
    console.log(`Client connected: ${userId}`);

    ws.on('close', () => {
        clients.delete(ws);
        console.log(`Client disconnected: ${userId}`);
    });

    ws.on('error', error => {
        console.error(`WebSocket error for user ${userId}: ${error}`);
        clients.delete(ws);
    });
});

function generateUniqueId() {
    return Math.random().toString(36).substring(2, 15);
}

function broadcast(data) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(data));
        }
    });
}

// Initialize database tables
db.serialize(() => {
    db.run(`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT, address TEXT, role TEXT)`);
    db.run(`CREATE TABLE stores (id INTEGER PRIMARY KEY, owner_id INTEGER, name TEXT, email TEXT, address TEXT, rating REAL, FOREIGN KEY(owner_id) REFERENCES users(id))`);
    db.run(`CREATE TABLE ratings (id INTEGER PRIMARY KEY, user_id INTEGER, store_id INTEGER, rating INTEGER)`);

    // Insert an admin user for testing
    const adminPassword = bcrypt.hashSync('@Madhav1234', 8);
    db.run(`INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)`, ['Madhav', 'madhavtokala@gmail.com', adminPassword, 'admin']);
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
    body('name').isLength({ min: 3, max: 60 }),
    body('email').isEmail(),
    body('password').isLength({ min: 8, max: 16 }).matches(/[A-Z]/).matches(/[!@#$%^&*]/),
    body('address').isLength({ max: 400 }),
    body('role').optional().isIn(['normal', 'admin']), // Add role validation, optional for now
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { name, email, password, address, role = 'normal' } = req.body; // Default role to 'normal' if not provided
    const hashedPassword = bcrypt.hashSync(password, 8);
    db.run(`INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, ?)`, [name, email, hashedPassword, address, role], function(err) {
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
        res.status(200).send({ auth: true, token, role: user.role }); // Send role on login
    });
});

// Get all users (Admin only)
app.get('/api/users', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).send("Access denied. Admins only.");
    }
    db.all(`SELECT id, name, email, address, role FROM users`, [], (err, users) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Error fetching users.");
        }
        res.json(users);
    });
});

// Add a new store (Admin only)
app.post('/api/stores', verifyToken, [
    body('ownerId').isInt().notEmpty(), // Ensure ownerId is provided and is an integer
    body('name').isLength({ min: 3, max: 100 }),
    body('address').isLength({ min: 5, max: 400 }),
    body('email').optional().isEmail(), // Optional email for the store
], (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).send("Access denied. Admins only.");
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { ownerId, name, email, address } = req.body;
    db.run(`INSERT INTO stores (owner_id, name, email, address, rating) VALUES (?, ?, ?, ?, ?)`, [ownerId, name, email, address, 0.0], function(err) {
        if (err) {
            console.error(err);
            return res.status(500).send("Error adding store.");
        }
        res.status(201).send({ id: this.lastID });
    });
});

// Get all stores with user's rating
app.get('/api/stores', verifyToken, (req, res) => {
    const userId = req.userId;
    db.all(`SELECT * FROM stores`, [], (err, stores) => {
        if (err) return res.status(500).send(err);

        const storesWithUserRating = stores.map(store => {
            return new Promise((resolve, reject) => {
                db.get(`SELECT rating FROM ratings WHERE user_id = ? AND store_id = ?`, [userId, store.id], (err, ratingData) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    resolve({
                        ...store,
                        userRating: ratingData ? ratingData.rating : null,
                    });
                });
            });
        });

        Promise.all(storesWithUserRating)
            .then(results => res.json(results))
            .catch(error => res.status(500).send(error));
    });
});

// Get all ratings (Admin only)
app.get('/api/ratings', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).send("Access denied. Admins only.");
    }
    db.all(`SELECT * FROM ratings`, [], (err, ratings) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Error fetching ratings.");
        }
        res.json(ratings);
    });
});

// Rate a store
app.post('/api/rate', verifyToken, (req, res) => {
    const { storeId, rating } = req.body;
    const userId = req.userId;

    db.run(`INSERT INTO ratings (user_id, store_id, rating) VALUES (?, ?, ?)`, [userId, storeId, rating], function(err) {
        if (err) return res.status(500).send("Error submitting rating.");
        const ratingId = this.lastID;

        // Fetch user name and the new average rating
        db.get(`SELECT name FROM users WHERE id = ?`, [userId], (err, user) => {
            if (user) {
                db.get(`SELECT AVG(rating) AS avgRating FROM ratings WHERE store_id = ?`, [storeId], (err, avgResult) => {
                    const averageRating = avgResult?.avgRating || 0;
                    broadcast({ type: 'newRating', storeId, rating, userName: user.name, userId, averageRating: averageRating.toFixed(2) });
                    res.status(201).send({ id: ratingId });
                });
            } else {
                res.status(201).send({ id: ratingId }); // Still send success even if user name fetch fails
            }
        });
    });
});

// Update a user's rating for a store
app.put('/api/rate/update', verifyToken, [
    body('storeId').notEmpty(),
    body('newRating').isInt({ min: 1, max: 5 }),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { storeId, newRating } = req.body;
    const userId = req.userId;

    db.run(`UPDATE ratings SET rating = ? WHERE user_id = ? AND store_id = ?`, [newRating, userId, storeId], function(err) {
        if (err) {
            console.error(err);
            return res.status(500).send("Error updating rating.");
        }
        if (this.changes > 0) {
            // Fetch user name and the new average rating
            db.get(`SELECT name FROM users WHERE id = ?`, [userId], (err, user) => {
                if (user) {
                    db.get(`SELECT AVG(rating) AS avgRating FROM ratings WHERE store_id = ?`, [storeId], (err, avgResult) => {
                        const averageRating = avgResult?.avgRating || 0;
                        broadcast({ type: 'updatedRating', storeId, rating: newRating, userName: user.name, userId, averageRating: averageRating.toFixed(2) });
                        res.status(200).send("Rating updated successfully.");
                    });
                } else {
                    res.status(200).send("Rating updated successfully."); // Still send success
                }
            });
        } else {
            res.status(404).send("Rating not found or no changes made.");
        }
    });
});

// Get store owner dashboard data
app.get('/api/owner/dashboard', verifyToken, (req, res) => {
    const ownerId = req.userId;

    // Fetch stores owned by the logged-in user
    db.all(`SELECT id, name FROM stores WHERE owner_id = ?`, [ownerId], (err, stores) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Error fetching owned stores.");
        }

        if (!stores || stores.length === 0) {
            return res.status(200).json([]); // No owned stores
        }

        const dashboardData = stores.map(store => {
            return new Promise((resolve, reject) => {
                // Fetch ratings for the current store
                db.all(`SELECT r.rating, u.name AS userName, r.user_id FROM ratings r JOIN users u ON r.user_id = u.id WHERE r.store_id = ?`, [store.id], (err, ratings) => {
                    if (err) {
                        reject(err);
                        return;
                    }

                    // Calculate average rating for the store
                    const totalRating = ratings.reduce((sum, rating) => sum + rating.rating, 0);
                    const averageRating = ratings.length > 0 ? (totalRating / ratings.length).toFixed(2) : '0.00';

                    resolve({
                        storeId: store.id,
                        storeName: store.name,
                        averageRating: averageRating,
                        ratings: ratings,
                    });
                });
            });
        });

        Promise.all(dashboardData)
            .then(results => res.json(results))
            .catch(error => res.status(500).send(error));
    });
});

// Update user password (requires authentication)
app.post('/api/user/password', verifyToken, [
    body('oldPassword').notEmpty(),
    body('newPassword').isLength({ min: 8, max: 16 }).matches(/[A-Z]/).matches(/[!@#$%^&*]/),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { oldPassword, newPassword } = req.body;
    const userId = req.userId;

    db.get(`SELECT password FROM users WHERE id = ?`, [userId], (err, user) => {
        if (err || !user) {
            return res.status(404).send("User not found.");
        }

        if (!bcrypt.compareSync(oldPassword, user.password)) {
            return res.status(401).send("Incorrect old password.");
        }

        const hashedPassword = bcrypt.hashSync(newPassword, 8);
        db.run(`UPDATE users SET password = ? WHERE id = ?`, [hashedPassword, userId], function(err) {
            if (err) {
                console.error(err);
                return res.status(500).send("Error updating password.");
            }
            res.status(200).send("Password updated successfully.");
        });
    });
});
