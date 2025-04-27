const fs = require('fs');
const path = require('path');

class Logger {
    constructor() {
        this.logDir = path.join(__dirname, '../logs');
        this.logFile = path.join(this.logDir, 'server.log');
        if (!fs.existsSync(this.logDir)) {
            fs.mkdirSync(this.logDir);
        }
    }

    log(message, level = 'INFO') {
        const timestamp = new Date().toISOString();
        const colors = {
            INFO: '\x1b[32m', // Green
            ERROR: '\x1b[31m', // Red
            WARN: '\x1b[33m' // Yellow
        };
        const color = colors[level] || '\x1b[0m';
        const logMessage = `[${timestamp}] [${level}] ${message}\n`;
        
     
        console.log(`${color}${logMessage}\x1b[0m`);
        
     
        fs.appendFileSync(this.logFile, logMessage, 'utf8');
    }

    info(message) {
        this.log(message, 'INFO');
    }

    error(message) {
        this.log(message, 'ERROR');
    }

    warn(message) {
        this.log(message, 'WARN');
    }
}

module.exports = new Logger();
