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
const CommandExecutor = require('./utils/commandExecutor');
const colors = require('./utils/colors');
const PentestCommands = require('./utils/pentestCommands');
const SearchCommands = require('./utils/searchCommands');

// Create readline interface for user input
const rl = createInterface({
    input: process.stdin,
    output: process.stdout
});

const question = (query) => new Promise((resolve) => rl.question(query, resolve));

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
            NEO4J_PASSWORD: await question('Enter Neo4j Password: ')
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
            const { apiKey, driver } = await getClients();

            // Check connections
            const session = driver.session();
            await session.run('RETURN 1');
            console.log(colors.success('✅ Neo4j connection successful'));
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
            console.log(colors.success('✅ Mistral AI connection successful'));

            // Create log directory if it doesn't exist
            const logDir = path.join(process.env.HOME, '.cybersec-cli');
            await fs.mkdir(logDir, { recursive: true });
            console.log(colors.success('✅ Log directory initialized'));

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
            switch (command) {
                case 'anls':
                    console.log(colors.info('\n🔍 Starting Log Analysis'));
                    console.log(colors.info('----------------------------------------'));
                    const logs = await createTerminalLogger().getRecentLogs();
                    const analysis = await analyzeWithMistral(apiKey, logs);
                    await storeInNeo4j(driver, analysis);
                    console.log(colors.success('\n✅ Analysis stored in Neo4j'));
                    break;

                case 'oanls':
                    console.log(colors.info('\n🔍 Starting Contextual Analysis'));
                    console.log(colors.info('----------------------------------------'));
                    const oLogs = await createTerminalLogger().getRecentLogs();
                    const graphContext = await storeInNeo4j.getGraphContext(driver);
                    console.log(colors.bullet, colors.analysisProgress('Retrieved graph context...'));
                    const situationAnalysis = await analyzeWithMistral(apiKey, oLogs, graphContext);
                    await storeInNeo4j(driver, situationAnalysis);
                    console.log(colors.success('\n✅ Analysis stored in Neo4j'));
                    break;

                case 'observe':
                    console.log(colors.info('Starting monitored terminal session...'));
                    const terminalLogger = createTerminalLogger();
                    
                    const terminal = spawn('bash', [], {
                        stdio: ['inherit', 'pipe', 'pipe']
                    });

                    terminal.stdout.on('data', async (data) => {
                        const output = data.toString();
                        await terminalLogger.log(output);
                        const termAnalysis = await analyzeWithMistral(apiKey, output);
                        await storeInNeo4j(driver, termAnalysis);
                    });

                    terminal.stderr.on('data', async (data) => {
                        const error = data.toString();
                        await terminalLogger.log(error, 'error');
                        const errorAnalysis = await analyzeWithMistral(apiKey, error);
                        await storeInNeo4j(driver, errorAnalysis);
                    });

                    console.log(colors.warning('Terminal observation started. Type "exit" to return to mask console.'));
                    break;

                case 'chat':
                    console.log(colors.info('\n💬 Starting Chat Session with Mistral AI'));
                    console.log(colors.info('----------------------------------------'));
                    console.log(colors.info('Type your messages and press Enter to send.'));
                    console.log(colors.info('Type "exit" to end the chat session.\n'));
                    
                    // Create a new readline interface specifically for chat
                    const chatInterface = createInterface({
                        input: process.stdin,
                        output: process.stdout,
                        prompt: colors.prompt('chat> '),
                        terminal: true,
                        historySize: 1000
                    });

                    // Disable the main console's input temporarily
                    consoleRL.pause();
                    
                    // Store the last keystroke time to prevent duplicates
                    let lastKeystrokeTime = 0;
                    const KEYSTROKE_THRESHOLD = 10; // milliseconds

                    // Override the _ttyWrite method to handle keystrokes
                    const originalTtyWrite = chatInterface._ttyWrite;
                    chatInterface._ttyWrite = function(s, key) {
                        const now = Date.now();
                        if (now - lastKeystrokeTime < KEYSTROKE_THRESHOLD) {
                            return;
                        }
                        lastKeystrokeTime = now;
                        originalTtyWrite.apply(this, arguments);
                    };

                    chatInterface.on('line', async (input) => {
                        const message = input.trim();

                        if (message.toLowerCase() === 'exit') {
                            console.log(colors.success('\nEnding chat session...'));
                            chatInterface.close();
                            consoleRL.resume();
                            consoleRL.prompt();
                            return;
                        }

                        if (message) {
                            try {
                                console.log(colors.timestamp('\nYou: ') + colors.commandOutput(message));
                                
                                const result = await chatWithMistral(apiKey, message);
                                
                                console.log(colors.timestamp('\nMistral: ') + 
                                    colors.analysisResult(result.response) + '\n');
                                
                                await storeInNeo4j(driver, {
                                    type: 'chat',
                                    query: message,
                                    response: result.response,
                                    timestamp: result.timestamp
                                });
                            } catch (error) {
                                console.error(colors.error('Error:'), colors.errorOutput(error.message));
                            }
                        }
                        
                        chatInterface.prompt();
                    });

                    chatInterface.on('SIGINT', () => {
                        console.log(colors.success('\nEnding chat session...'));
                        chatInterface.close();
                        consoleRL.resume();
                        consoleRL.prompt();
                    });

                    chatInterface.prompt();
                    break;

                case 'clear':
                    console.clear();
                    break;

                case 'help':
                    console.log(colors.subHeader('\nAvailable commands:'));
                    console.log(colors.header('\nBuilt-in commands:'));
                    console.log(colors.helpCommand('anls', 'Analyze terminal logs'));
                    console.log(colors.helpCommand('oanls', 'Analyze logs with graph context'));
                    console.log(colors.helpCommand('observe', 'Start monitored terminal session'));
                    console.log(colors.helpCommand('chat', 'Start chat session with Mistral AI'));
                    console.log(colors.helpCommand('clear', 'Clear the console'));
                    console.log(colors.helpCommand('help', 'Show this help message'));
                    console.log(colors.helpCommand('exit', 'Exit the console'));
                    console.log(colors.header('\nSystem commands:'));
                    console.log(colors.info('  All standard Linux/Ubuntu commands are supported'));
                    console.log(colors.info('  Examples: ls, ps, netstat, ifconfig, etc.'));
                    break;

                case 'exit':
                    console.log(colors.success('\nGoodbye! 👋'));
                    consoleRL.close();
                    process.exit(0);
                    break;

                case 'recon':
                case 'vuln':
                case 'network':
                case 'exploit':
                case 'web':
                case 'wireless':
                    const pentestCommands = PentestCommands.getPentestCommands();
                    const toolset = pentestCommands[command];
                    
                    console.log(colors.header(`\n🛠️ ${command.toUpperCase()} Tools`));
                    console.log(colors.info('----------------------------------------'));
                    
                    Object.entries(toolset.subcommands).forEach(([tool, cmd]) => {
                        console.log(colors.helpCommand(tool, cmd));
                    });
                    
                    const toolChoice = await question(colors.prompt('\nSelect tool: '));
                    if (toolset.subcommands[toolChoice]) {
                        const target = await question(colors.prompt('Enter target: '));
                        const fullCommand = `${toolset.subcommands[toolChoice]} ${target}`;
                        
                        console.log(colors.info('\nExecuting command...'));
                        const result = await PentestCommands.executeCommand(fullCommand);
                        
                        if (result.success) {
                            console.log(colors.success('\nCommand Output:'));
                            console.log(colors.commandOutput(result.output));
                            
                            // Analyze with Mistral AI
                            const analysis = await analyzeWithMistral(
                                apiKey,
                                await PentestCommands.analyzeWithAI(apiKey, result.output, command)
                            );
                            
                            console.log(colors.header('\n📊 AI Analysis'));
                            console.log(colors.info('----------------------------------------'));
                            console.log(colors.analysis(analysis.analysis));
                            
                            // Store in Neo4j
                            await storeInNeo4j(driver, {
                                type: 'pentest',
                                tool: toolChoice,
                                command: fullCommand,
                                output: result.output,
                                analysis: analysis.analysis,
                                timestamp: new Date().toISOString()
                            });
                        } else {
                            console.error(colors.error('Error:'), colors.errorOutput(result.error));
                        }
                    }
                    break;

                case 'search':
                    console.log(colors.header('\n🔍 Advanced Security Research'));
                    console.log(colors.info('----------------------------------------'));
                    console.log(colors.helpCommand('exploitdb', 'Search ExploitDB'));
                    console.log(colors.helpCommand('github', 'Search GitHub repositories'));
                    console.log(colors.helpCommand('cve', 'Search CVE database'));
                    console.log(colors.helpCommand('blogs', 'Search security blogs'));
                    console.log(colors.helpCommand('all', 'Search across all platforms'));
                    
                    const searchType = await question(colors.prompt('\nSelect search type: '));
                    const searchQuery = await question(colors.prompt('Enter search query: '));
                    
                    console.log(colors.info('\nSearching across multiple sources...'));
                    
                    try {
                        let results = [];
                        
                        if (searchType === 'all' || searchType === 'exploitdb') {
                            console.log(colors.info('Searching ExploitDB...'));
                            const exploitResults = await SearchCommands.searchExploitDB(searchQuery);
                            if (exploitResults.success) {
                                console.log(SearchCommands.formatSearchResults(exploitResults));
                                results.push(exploitResults);
                            }
                        }
                        
                        if (searchType === 'all' || searchType === 'github') {
                            console.log(colors.info('Searching GitHub...'));
                            const githubResults = await SearchCommands.searchGitHub(searchQuery);
                            if (githubResults.success) {
                                console.log(SearchCommands.formatSearchResults(githubResults));
                                results.push(githubResults);
                            }
                        }

                        if (searchType === 'all' || searchType === 'cve') {
                            console.log(colors.info('Searching CVE Database...'));
                            const cveResults = await SearchCommands.searchCVE(searchQuery);
                            if (cveResults.success) {
                                console.log(SearchCommands.formatSearchResults(cveResults));
                                results.push(cveResults);
                            }
                        }

                        if (searchType === 'all' || searchType === 'blogs') {
                            console.log(colors.info('Searching Security Blogs...'));
                            const blogResults = await SearchCommands.searchSecurityBlogs(searchQuery);
                            if (blogResults.success) {
                                console.log(SearchCommands.formatSearchResults(blogResults));
                                results.push(blogResults);
                            }
                        }

                        // Analyze results with Mistral AI
                        if (results.length > 0) {
                            const searchAnalysis = await SearchCommands.analyzeSearchResults(results, searchQuery);
                            const analysis = await analyzeWithMistral(
                                apiKey,
                                await PentestCommands.analyzeSearchResults(apiKey, searchAnalysis, searchQuery)
                            );
                            
                            console.log(colors.header('\n📊 AI Analysis'));
                            console.log(colors.info('----------------------------------------'));
                            console.log(colors.analysis(analysis.analysis));
                            
                            // Store in Neo4j
                            await storeInNeo4j(driver, {
                                type: 'search',
                                query: searchQuery,
                                results: searchAnalysis,
                                analysis: analysis.analysis,
                                timestamp: new Date().toISOString()
                            });
                        }
                    } catch (error) {
                        console.error(colors.error('Error during search:'), colors.errorOutput(error.message));
                    }
                    break;

                default:
                    if (command !== '') {
                        if (CommandExecutor.isSystemCommand(command)) {
                            await CommandExecutor.executeWithAnalysis(command, apiKey, driver);
                        } else {
                            console.log(colors.error('❌ Unknown command. Type "help" for available commands.'));
                        }
                    }
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
