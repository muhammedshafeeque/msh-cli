const chalk = require('chalk');

const colors = {
    // Command types
    command: chalk.cyan,
    systemCommand: chalk.magenta,
    
    // Status indicators
    success: chalk.green,
    error: chalk.red,
    warning: chalk.yellow,
    info: chalk.blue,
    
    // Highlights
    highlight: chalk.yellow.bold,
    important: chalk.red.bold,
    
    // UI elements
    prompt: chalk.green.bold,
    header: chalk.blue.bold,
    subHeader: chalk.cyan.bold,
    
    // Data types
    timestamp: chalk.gray,
    path: chalk.cyan.underline,
    
    // Analysis
    analysis: chalk.magenta,
    security: chalk.red.bold,
    
    // Custom styling functions
    commandOutput: (text) => chalk.gray(text),
    errorOutput: (text) => chalk.red.dim(text),
    helpCommand: (cmd, desc) => `  ${chalk.cyan(cmd.padEnd(8))} - ${chalk.gray(desc)}`,
    
    // Analysis specific colors
    analysisProgress: chalk.yellow.dim,
    analysisResult: chalk.cyan,
    jsonKey: chalk.magenta,
    jsonValue: chalk.green,
    
    // Progress indicators
    progressBar: (progress) => chalk.blue(`[${'='.repeat(progress)}${' '.repeat(20-progress)}]`),
    bullet: chalk.yellow('•'),
    
    // Formatted JSON output
    formatJSON: (json) => {
        try {
            const parsed = typeof json === 'string' ? JSON.parse(json) : json;
            return Object.entries(parsed)
                .map(([key, value]) => `  ${chalk.magenta(key)}: ${chalk.green(value)}`)
                .join('\n');
        } catch {
            return chalk.gray(json);
        }
    },

    // Analysis section
    analysisSection: (title, content) => `${chalk.yellow.bold(title)}:\n${chalk.cyan(content)}\n`,

    critical: (text) => chalk.red.bold(text),
    high: (text) => chalk.red(text),
    medium: (text) => chalk.yellow(text),
    low: (text) => chalk.green(text),
    table: (text) => chalk.cyan(text),
    year: (text) => chalk.blue.bold(text),
    analysis: (text) => chalk.cyan(text),
    subheader: (text) => `\x1b[36m${text}\x1b[0m`,
    table: (text) => `\x1b[37m${text}\x1b[0m`,
    analysis: (text) => `\x1b[38;5;147m${text}\x1b[0m`
};

module.exports = colors; 