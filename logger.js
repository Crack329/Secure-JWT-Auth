const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Create logs directory if it doesn't exist
const logDir = 'logs';
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
}

// Define log format
const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
);

// Create logger instance
const logger = winston.createLogger({
    level: 'debug',
    format: logFormat,
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.printf(({ timestamp, level, message }) => {
                    return `${timestamp} [${level}]: ${message}`;
                })
            )
        }),
        new winston.transports.File({ 
            filename: path.join('logs', 'combined.log'),
            maxsize: 5242880,
            maxFiles: 5
        }),
        new winston.transports.File({ 
            filename: path.join('logs', 'security.log'),
            level: 'warn',
            maxsize: 5242880,
            maxFiles: 5
        }),
        new winston.transports.File({ 
            filename: path.join('logs', 'error.log'),
            level: 'error',
            maxsize: 5242880,
            maxFiles: 5
        })
    ]
});

// Security event logger
const logSecurityEvent = (event, user, ip, details = {}) => {
    logger.warn({
        type: 'SECURITY_EVENT',
        event: event,
        user: user || 'anonymous',
        ip: ip || 'unknown',
        timestamp: new Date().toISOString(),
        ...details
    });
};

// Authentication attempt logger
const logAuthAttempt = (username, success, ip, reason = '') => {
    const level = success ? 'info' : 'warn';
    logger.log(level, {
        type: 'AUTH_ATTEMPT',
        username: username,
        success: success,
        ip: ip || 'unknown',
        reason: reason,
        timestamp: new Date().toISOString()
    });
};

module.exports = {
    logger,
    logSecurityEvent,
    logAuthAttempt
};