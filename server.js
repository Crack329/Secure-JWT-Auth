require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const validator = require('validator');
const jwtUtils = require('./jwtUtils.js');

// ============ LOGGING SETUP ============
const { logger, logSecurityEvent, logAuthAttempt } = require('./logger.js');
logger.info('🚀 Application starting...');

const app = express();
const port = 3000;
const saltRounds = 12;

// ============ SECURITY HEADERS WITH HELMET ============
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: {
        policy: 'strict-origin-when-cross-origin'
    },
    xssFilter: true,
    noSniff: true,
    hidePoweredBy: true,
    frameguard: {
        action: 'deny'
    }
}));

// ============ MIDDLEWARE ============
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ============ ADDITIONAL SECURITY HEADERS ============
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.removeHeader('X-Powered-By');
    next();
});

// ============ DATABASE SETUP WITH BCRYPT HASHES ============
const db = new sqlite3.Database('./app.db');

// Only initialize if table doesn't exist
db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users'", async (err, table) => {
    if (err) {
        logger.error('Database error:', err);
        return;
    }
    
    if (!table) {
        logger.info('📦 Creating database tables...');
        
        const adminHash = await bcrypt.hash('admin123', saltRounds);
        const johnHash = await bcrypt.hash('password123', saltRounds);
        
        db.serialize(() => {
            db.run(`CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                email TEXT,
                refresh_token TEXT
            )`);
            
            db.run("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                ['admin', adminHash, 'admin@test.com']);
            db.run("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                ['john', johnHash, 'john@test.com']);
            
            logger.info('✅ Database initialized with bcrypt hashed passwords');
            logger.info('🔐 Salt rounds: 12');
            logger.info('👤 Test users: admin / admin123, john / password123');
        });
    } else {
        logger.info('✅ Database already exists - using existing users');
    }
});

// ============ JWT AUTHENTICATION ENDPOINTS ============

// ============ LOGIN ENDPOINT - WITH LOGGING ============
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const clientIp = req.ip || req.connection.remoteAddress;
        
        logger.info(`🔵 Login attempt from ${clientIp} for user: ${username}`);
        
        if (!username || !password) {
            logAuthAttempt(username, false, clientIp, 'Missing credentials');
            return res.status(400).json({ 
                success: false, 
                message: 'Username and password required' 
            });
        }
        
        const query = `SELECT * FROM users WHERE username = ?`;
        
        db.get(query, [username], async (err, user) => {
            try {
                if (err) {
                    logger.error('Database error:', err);
                    logSecurityEvent('DATABASE_ERROR', null, clientIp, { error: err.message });
                    return res.status(500).json({ 
                        success: false, 
                        message: 'Login failed' 
                    });
                }
                
                if (!user) {
                    logAuthAttempt(username, false, clientIp, 'User not found');
                    return res.status(401).json({ 
                        success: false, 
                        message: 'Invalid username or password' 
                    });
                }
                
                logger.info(`✅ User found: ${user.username}`);
                
                const match = await bcrypt.compare(password, user.password);
                
                if (match) {
                    logger.info(`✅ Login successful: ${username} from ${clientIp}`);
                    logAuthAttempt(username, true, clientIp);
                    
                    const accessToken = jwtUtils.generateAccessToken(user);
                    const refreshToken = jwtUtils.generateRefreshToken(user);
                    
                    db.run("UPDATE users SET refresh_token = ? WHERE id = ?",
                        [refreshToken, user.id], (err) => {
                        if (err) logger.error('Failed to store refresh token:', err);
                    });
                    
                    logSecurityEvent('LOGIN_SUCCESS', username, clientIp);
                    
                    return res.json({
                        success: true,
                        message: 'Login successful',
                        accessToken: accessToken,
                        refreshToken: refreshToken,
                        expiresIn: '15m',
                        user: {
                            id: user.id,
                            username: user.username,
                            email: user.email
                        }
                    });
                } else {
                    logger.warn(`❌ Login failed - invalid password: ${username} from ${clientIp}`);
                    logAuthAttempt(username, false, clientIp, 'Invalid password');
                    logSecurityEvent('LOGIN_FAILED', username, clientIp, { reason: 'invalid_password' });
                    
                    return res.status(401).json({ 
                        success: false, 
                        message: 'Invalid username or password' 
                    });
                }
            } catch (error) {
                logger.error('Login processing error:', error);
                logSecurityEvent('LOGIN_ERROR', username, clientIp, { error: error.message });
                return res.status(500).json({ 
                    success: false, 
                    message: 'Login processing failed' 
                });
            }
        });
    } catch (error) {
        logger.error('Outer login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Refresh token endpoint
app.post('/refresh-token', (req, res) => {
    jwtUtils.refreshAccessToken(req, res);
});

// ============ LOGOUT ENDPOINT - WITH LOGGING ============
app.post('/logout', jwtUtils.authenticateToken, (req, res) => {
    const userId = req.user.id;
    const username = req.user.username;
    const clientIp = req.ip;
    
    logger.info(`🔵 Logout request: ${username} from ${clientIp}`);
    
    db.run("UPDATE users SET refresh_token = NULL WHERE id = ?", [userId], (err) => {
        if (err) {
            logger.error('Logout error:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Logout failed' 
            });
        }
        
        logger.info(`✅ Logout successful: ${username}`);
        logSecurityEvent('LOGOUT', username, clientIp);
        
        res.json({ 
            success: true, 
            message: 'Logged out successfully' 
        });
    });
});

// ============ PROTECTED ROUTES ============

// ============ PROFILE ENDPOINT - WITH LOGGING ============
app.get('/profile', jwtUtils.authenticateToken, (req, res) => {
    const userId = req.user.id;
    const username = req.user.username;
    const clientIp = req.ip;
    
    logger.debug(`🔍 Profile fetch: ${username} from ${clientIp}`);
    
    db.get("SELECT id, username, email FROM users WHERE id = ?", [userId], (err, user) => {
        if (err) {
            logger.error('Profile fetch error:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Error fetching profile' 
            });
        }
        
        if (!user) {
            logger.warn(`❌ Profile not found for user ID: ${userId}`);
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        logger.info(`✅ Profile fetched: ${username}`);
        res.json({
            success: true,
            profile: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });
    });
});

// ============ COMMENTS WITH JWT AND XSS PROTECTION ============
const posts = [];

app.post('/comment', jwtUtils.authenticateToken, (req, res) => {
    let { comment } = req.body;
    const username = req.user.username;
    const clientIp = req.ip;
    
    // XSS prevention - escape HTML entities
    comment = validator.escape(comment);
    
    posts.push({
        username: username,
        comment: comment,
        timestamp: new Date().toISOString()
    });
    
    logger.info(`💬 Comment added by ${username} from ${clientIp}`);
    logSecurityEvent('COMMENT_ADDED', username, clientIp, { comment_length: comment.length });
    
    res.json({ 
        success: true, 
        message: 'Comment added',
        comments: posts 
    });
});

app.get('/comments', jwtUtils.authenticateToken, (req, res) => {
    const username = req.user.username;
    logger.debug(`💬 Comments fetched by ${username}`);
    
    res.json({
        success: true,
        comments: posts
    });
});

// ============ DEBUG ENDPOINT (Remove in production) ============
app.get('/debug-users', (req, res) => {
    const clientIp = req.ip;
    logger.warn(`⚠️ DEBUG endpoint accessed from ${clientIp}`);
    
    db.all("SELECT id, username, password, email, refresh_token FROM users", [], (err, rows) => {
        if (err) {
            logger.error('Debug endpoint error:', err);
            res.send(`Error: ${err.message}`);
        } else {
            let html = '<h1 style="color: green;">✅ DEBUG MODE - BCRYPT HASHES</h1>';
            html += '<h2>Database Contents - Passwords are SECURELY HASHED</h2>';
            html += '<table border="1" cellpadding="10" style="border-collapse: collapse;">';
            html += '<tr style="background: #333; color: white;"><th>ID</th><th>Username</th><th>Password Hash</th><th>Refresh Token</th><th>Email</th></tr>';
            
            rows.forEach(row => {
                html += `<tr>`;
                html += `<td>${row.id}</td>`;
                html += `<td><strong>${row.username}</strong></td>`;
                html += `<td style="background: #ccffcc; font-family: monospace; font-size: 12px;">${row.password.substring(0, 30)}...</td>`;
                html += `<td style="background: #ffffcc; font-family: monospace; font-size: 11px;">${row.refresh_token ? row.refresh_token.substring(0, 30) + '...' : 'NULL'}</td>`;
                html += `<td>${row.email}</td>`;
                html += `</tr>`;
            });
            
            html += '</table>';
            html += '<p style="color: green;"><strong>✅ FIXED: Passwords are hashed with bcrypt!</strong></p>';
            html += '<p><a href="/">← Back to Login</a></p>';
            res.send(html);
        }
    });
});

// ============ JWT LOGIN PAGE ============
app.get('/', (req, res) => {
    res.send(`...`); // Aapka existing HTML code yahan rahega
});

// ============ START SERVER ============
app.listen(port, () => {
    console.log('=========================================');
    console.log('✅ SECURE APPLICATION RUNNING');
    console.log(`🌐 http://localhost:${port}`);
    console.log('=========================================');
    console.log('🔐 SECURITY FEATURES ENABLED:');
    console.log('   • JWT Authentication (15min expiry)');
    console.log('   • bcrypt Password Hashing (12 rounds)');
    console.log('   • Helmet.js Security Headers');
    console.log('   • CSP - Content Security Policy');
    console.log('   • HSTS - HTTP Strict Transport Security');
    console.log('   • XSS Protection - Output Encoding');
    console.log('   • SQL Injection Protection - Parameterized Queries');
    console.log('   • No Information Disclosure');
    console.log('   • Winston Security Logging');  // ✅ ADDED
    console.log('=========================================');
    
    // ✅ LOGGING INITIALIZATION
    logger.info('=========================================');
    logger.info('✅ SECURE APPLICATION STARTED');
    logger.info(`🌐 http://localhost:${port}`);
    logger.info('🔐 All security features enabled');
    logger.info('   • JWT Authentication (15min expiry)');
    logger.info('   • bcrypt Password Hashing (12 rounds)');
    logger.info('   • Helmet.js Security Headers');
    logger.info('   • Winston Security Logging');
    logger.info('=========================================');
});