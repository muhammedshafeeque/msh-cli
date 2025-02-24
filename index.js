#!/usr/bin/env node

const { program } = require('commander');
const { exec } = require('child_process');
const { Mistral } = require('@mistralai/mistralai');
const neo4j = require('neo4j-driver');
const { spawn } = require('child_process');
const { createTerminalLogger } = require('./utils/terminalLogger');
const { analyzeWithMistral, chatWithMistral } = require('./utils/mistralAnalyzer');
const { storeInNeo4j } = require('./utils/neo4jHandler');
const path = require('path');
const fs = require('fs').promises;
const { createInterface } = require('readline');
const { executeCommand, handleAnalysisCommand } = require('./utils/commandExecutor');
const colors = require('./utils/colors');
const PentestCommands = require('./utils/pentestCommands');
const SearchCommands = require('./utils/searchCommands');
const { execSync } = require('child_process');

// Create readline interface for user input
const rl = createInterface({
    input: process.stdin,
    output: process.stdout
});

const question = (query) => new Promise((resolve) => rl.question(query, resolve));

// Add root permission check function
async function checkRootPermissions() {
    try {
        const userId = execSync('id -u').toString().trim();
        if (userId !== '0') {
            console.log(colors.error('\n❌ Error: Root permissions required'));
            console.log(colors.info('Please run the tool with sudo:'));
            console.log(colors.command('sudo mask'));
            process.exit(1);
        }
        return true;
    } catch (error) {
        console.error(colors.error('\n❌ Error checking permissions:'), colors.errorOutput(error.message));
        process.exit(1);
    }
}

// Function to check and setup environment variables
async function setupEnvironment() {
    const envPath = path.join(process.env.HOME, '.cybersec-cli', '.env');
    
    try {
        await fs.access(envPath);
        // If file exists, load it
        require('dotenv').config({ path: envPath });
    } catch {
        console.log('🔧 First-time setup: Configuring environment variables');
        console.log('----------------------------------------');
        
        const config = {
            MISTRAL_API_KEY: await question('Enter Mistral AI API Key: '),
            NEO4J_URI: await question('Enter Neo4j URI (default: bolt://localhost:7687): ') || 'bolt://localhost:7687',
            NEO4J_USER: await question('Enter Neo4j Username (default: neo4j): ') || 'neo4j',
            NEO4J_PASSWORD: await question('Enter Neo4j Password: '),
            GOOGLE_API_KEY: await question('Enter Google API Key (optional): '),
            GOOGLE_CX: await question('Enter Google Custom Search CX (optional): '),
            GITHUB_TOKEN: await question('Enter GitHub API Token (optional): ')
        };

        // Create .cybersec-cli directory if it doesn't exist
        await fs.mkdir(path.join(process.env.HOME, '.cybersec-cli'), { recursive: true });

        // Write environment variables to file
        const envContent = Object.entries(config)
            .map(([key, value]) => `${key}=${value}`)
            .join('\n');
        
        await fs.writeFile(envPath, envContent);
        
        // Set environment variables for current session
        Object.entries(config).forEach(([key, value]) => {
            process.env[key] = value;
        });

        console.log('✅ Environment variables configured successfully');
    } finally {
        rl.close();
    }
}

// Add a function to get initialized clients
async function getClients() {
    if (!process.env.MISTRAL_API_KEY) {
        await setupEnvironment();
    }
    
    const driver = neo4j.driver(
        process.env.NEO4J_URI || 'bolt://localhost:7687',
        neo4j.auth.basic(
            process.env.NEO4J_USER || 'neo4j',
            process.env.NEO4J_PASSWORD || 'password'
        )
    );
    
    return { apiKey: process.env.MISTRAL_API_KEY, driver };
}

program
    .version('1.0.0')
    .description('Cybersecurity CLI tool interactive console')
    .action(async () => {
        try {
            // Check root permissions first
            await checkRootPermissions();
            console.log(colors.success('✓ Root permissions verified'));
            console.log(colors.warning('\n⚠️ Warning: This tool should only be used on authorized systems'));

            const { apiKey, driver } = await getClients();

            // Check connections
            const session = driver.session();
            await session.run('RETURN 1');
            console.log(colors.success('✓ Neo4j connection successful'));
            session.close();

            // Test Mistral AI connection
            const mistral = new Mistral({
                apiKey: apiKey
            });
            await mistral.chat.complete({
                model: "mistral-small-latest",
                messages: [{ role: "user", content: "test" }],
                stream: false
            });
            console.log(colors.success('✓ Mistral AI connection successful'));

            // Create log directory if it doesn't exist
            const logDir = path.join(process.env.HOME, '.cybersec-cli');
            await fs.mkdir(logDir, { recursive: true });
            console.log(colors.success('✓ Log directory initialized'));

            // Display banner
            console.log(colors.header('\n🎭 MASK - Advanced Security CLI'));
            console.log(colors.info('----------------------------------------'));
            console.log(colors.warning('⚠️  For authorized penetration testing only'));
            console.log(colors.info('----------------------------------------\n'));

            // Start the interactive console
            await startInteractiveConsole(apiKey, driver);

        } catch (error) {
            console.error(colors.error('❌ Error during initialization:'), colors.errorOutput(error));
            if (error.message.includes('Authentication')) {
                console.log('\nTip: To reconfigure environment variables, delete the .env file in ~/.cybersec-cli/');
            }
            process.exit(1);
        }
    });

// Command: anls - Analyze terminal logs
program
    .command('anls')
    .description('Analyze terminal logs with Mistral AI and store in Neo4j')
    .action(async () => {
        try {
            await checkRootPermissions();
            const { apiKey, driver } = await getClients();
            const logs = await createTerminalLogger().getRecentLogs();
            const analysis = await analyzeWithMistral(apiKey, logs);
            await storeInNeo4j(driver, analysis);
            console.log('Analysis completed and stored in Neo4j');
        } catch (error) {
            console.error('Error during analysis:', error);
        }
    });

// Command: oanls - Analyze logs with graph context
program
    .command('oanls')
    .description('Find possible situations by analyzing logs with graph database context')
    .action(async () => {
        try {
            await checkRootPermissions();
            const { apiKey, driver } = await getClients();
            const logs = await createTerminalLogger().getRecentLogs();
            const graphContext = await storeInNeo4j.getGraphContext(driver);
            const analysis = await analyzeWithMistral(apiKey, logs, graphContext);
            console.log('Situation Analysis:', analysis);
        } catch (error) {
            console.error('Error during situation analysis:', error);
        }
    });

// Command: observe - Start new terminal instance with monitoring
program
    .command('observe')
    .description('Start new terminal instance and record/analyze activities')
    .action(async () => {
        try {
            await checkRootPermissions();
            const { apiKey, driver } = await getClients();
            const terminalLogger = createTerminalLogger();
            
            const terminal = spawn('bash', [], {
                stdio: ['inherit', 'pipe', 'pipe']
            });

            terminal.stdout.on('data', async (data) => {
                const output = data.toString();
                await terminalLogger.log(output);
                const analysis = await analyzeWithMistral(apiKey, output);
                await storeInNeo4j(driver, analysis);
            });

            terminal.stderr.on('data', async (data) => {
                const error = data.toString();
                await terminalLogger.log(error, 'error');
                const analysis = await analyzeWithMistral(apiKey, error);
                await storeInNeo4j(driver, analysis);
            });

            console.log('Terminal observation started. Type "exit" to stop.');
        } catch (error) {
            console.error('Error starting observation:', error);
        }
    });

// Add this new function for the interactive console
async function startInteractiveConsole(apiKey, driver) {
    const consoleRL = createInterface({
        input: process.stdin,
        output: process.stdout,
        prompt: colors.prompt('mask> ')
    });

    console.log(colors.header('\n🎭 Welcome to MASK Interactive Console'));
    console.log(colors.info('----------------------------------------'));
    console.log(colors.subHeader('Available commands:'));
    console.log(colors.helpCommand('anls', 'Analyze terminal logs'));
    console.log(colors.helpCommand('oanls', 'Analyze logs with graph context'));
    console.log(colors.helpCommand('observe', 'Start monitored terminal session'));
    console.log(colors.helpCommand('chat', 'Start chat session with Mistral AI'));
    console.log(colors.helpCommand('clear', 'Clear the console'));
    console.log(colors.helpCommand('help', 'Show this help message'));
    console.log(colors.helpCommand('exit', 'Exit the console'));
    console.log(colors.header('\nPenetration Testing Commands:'));
    console.log(colors.helpCommand('recon', 'Reconnaissance tools and automation'));
    console.log(colors.helpCommand('vuln', 'Vulnerability assessment tools'));
    console.log(colors.helpCommand('network', 'Network analysis tools'));
    console.log(colors.helpCommand('exploit', 'Exploitation frameworks'));
    console.log(colors.helpCommand('web', 'Web application testing tools'));
    console.log(colors.helpCommand('wireless', 'Wireless network testing'));
    console.log(colors.header('\nSearch Commands:'));
    console.log(colors.helpCommand('search', 'Search for security resources'));
    console.log(colors.info('----------------------------------------\n'));

    consoleRL.prompt();

    consoleRL.on('line', async (line) => {
        const command = line.trim();

        try {
            const analysisCommands = ['anls', 'summary'];
            if (analysisCommands.includes(command)) {
                await handleAnalysisCommand(command);
            } else {
                await executeCommand(command);
            }
        } catch (error) {
            console.error(colors.error('❌ Error:'), colors.errorOutput(error.message));
        }

        if (command !== 'chat') {
            consoleRL.prompt();
        }
    });

    consoleRL.on('close', () => {
        console.log(colors.success('\nGoodbye! 👋'));
        process.exit(0);
    });
}

// Parse arguments
program.parse(process.argv);

// If no command is provided, show help
if (!process.argv.slice(2).length) {
    program.outputHelp();
}
