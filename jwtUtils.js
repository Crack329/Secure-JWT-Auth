const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

// Generate secure random secrets if not provided
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_EXPIRY = process.env.JWT_EXPIRY || '15m';
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET || crypto.randomBytes(32).toString('hex');
const REFRESH_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '7d';

console.log('✅ JWT Utils initialized');
console.log('🔐 JWT Secret: [SECURED]');
console.log(`⏰ JWT Expiry: ${JWT_EXPIRY}`);

// Generate access token
const generateAccessToken = (user) => {
    try {
        if (!user || !user.id) {
            throw new Error('Invalid user object');
        }
        
        const payload = {
            id: user.id,
            username: user.username || '',
            email: user.email || '',
            tokenType: 'access'
        };
        
        return jwt.sign(payload, JWT_SECRET, { 
            expiresIn: JWT_EXPIRY,
            algorithm: 'HS256'
        });
    } catch (error) {
        console.error('❌ Access token generation failed:', error.message);
        throw error;
    }
};

// Generate refresh token
const generateRefreshToken = (user) => {
    try {
        if (!user || !user.id) {
            throw new Error('Invalid user object');
        }
        
        const payload = {
            id: user.id,
            tokenType: 'refresh'
        };
        
        return jwt.sign(payload, REFRESH_SECRET, { 
            expiresIn: REFRESH_EXPIRY,
            algorithm: 'HS256'
        });
    } catch (error) {
        console.error('❌ Refresh token generation failed:', error.message);
        throw error;
    }
};

// Verify access token middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access token required'
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('❌ Token verification failed:', err.message);
            
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({
                    success: false,
                    message: 'Token expired'
                });
            }
            
            return res.status(403).json({
                success: false,
                message: 'Invalid token'
            });
        }

        req.user = user;
        next();
    });
};

// Verify refresh token
const verifyRefreshToken = (token) => {
    try {
        return jwt.verify(token, REFRESH_SECRET);
    } catch (error) {
        console.error('❌ Refresh token verification failed:', error.message);
        return null;
    }
};

// Refresh access token endpoint handler
const refreshAccessToken = (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(401).json({
                success: false,
                message: 'Refresh token required'
            });
        }

        const user = verifyRefreshToken(refreshToken);
        if (!user) {
            return res.status(403).json({
                success: false,
                message: 'Invalid refresh token'
            });
        }

        const newAccessToken = generateAccessToken({
            id: user.id,
            username: user.username
        });

        res.json({
            success: true,
            accessToken: newAccessToken,
            expiresIn: JWT_EXPIRY
        });
    } catch (error) {
        console.error('❌ Refresh token error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to refresh token'
        });
    }
};

module.exports = {
    generateAccessToken,
    generateRefreshToken,
    authenticateToken,
    refreshAccessToken,
    verifyRefreshToken
};