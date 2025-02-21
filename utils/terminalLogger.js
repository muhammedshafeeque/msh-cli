const fs = require('fs').promises;
const path = require('path');

class TerminalLogger {
    constructor() {
        this.logPath = path.join(process.env.HOME, '.cybersec-cli', 'terminal.log');
    }

    async log(content, type = 'info') {
        const timestamp = new Date().toISOString();
        const logEntry = `[${timestamp}] [${type}] ${content}\n`;
        
        await fs.appendFile(this.logPath, logEntry);
    }

    async getRecentLogs(limit = 100) {
        const content = await fs.readFile(this.logPath, 'utf-8');
        return content.split('\n').slice(-limit).join('\n');
    }
}

const createTerminalLogger = () => new TerminalLogger();

module.exports = { createTerminalLogger }; 