const { exec, execSync } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const colors = require('./colors');
const { analyzeWithMistral, analyzeOutput } = require('./mistralAnalyzer');
const { storeInNeo4j } = require('./neo4jHandler');
const SearchCommands = require('./searchCommands');
const CodeAnalyzer = require('./codeAnalyzer');
const question = require('./question');
const HackingCommands = require('./hackingCommands');

class CommandExecutor {
    static async executeCommand(command) {
        try {
            const { stdout, stderr } = await execPromise(command);
            return {
                success: true,
                output: stdout,
                error: stderr,
                command: command
            };
        } catch (error) {
            return {
                success: false,
                output: '',
                error: error.message,
                command: command
            };
        }
    }

    static isSystemCommand(command) {
        // List of common Linux/Ubuntu/Kali commands and tools
        const systemCommands = [
            // Basic Linux commands
            'ls', 'cd', 'pwd', 'cp', 'mv', 'rm', 'mkdir', 'touch',
            'cat', 'grep', 'find', 'ps', 'top', 'kill', 'systemctl',
            'apt', 'apt-get', 'sudo', 'chmod', 'chown', 'ping',
            'ifconfig', 'ip', 'netstat', 'ss', 'curl', 'wget',
            'uname', 'whoami', 'who', 'date', 'df', 'du', 'free',
            'history', 'man', 'tar', 'zip', 'unzip', 'ssh', 'scp',
            'git', 'docker', 'python', 'python3', 'pip', 'npm',

            // Information Gathering
            'nmap', 'masscan', 'dmitry', 'maltego', 'recon-ng',
            'spiderfoot', 'theharvester', 'whois', 'dig', 'fierce',
            'dnsenum', 'dnsrecon', 'sublist3r',

            // Vulnerability Analysis
            'nikto', 'wpscan', 'sqlmap', 'nessus', 'openvas',
            'lynis', 'nuclei', 'arachni', 'dirb', 'gobuster',
            'wfuzz', 'ffuf', 'skipfish',

            // Web Application Analysis
            'burpsuite', 'zaproxy', 'owasp-zap', 'xsser',
            'wafw00f', 'whatweb', 'davtest', 'cadaver',
            'skipfish', 'paros', 'w3af',

            // Database Assessment
            'sqlmap', 'sqlninja', 'sqlsus', 'hexorbase',
            'oscanner', 'mdb-tools',

            // Password Attacks
            'hydra', 'john', 'johnny', 'hashcat', 'ophcrack',
            'rainbowcrack', 'crunch', 'cewl', 'medusa', 'ncrack',

            // Wireless Attacks
            'aircrack-ng', 'wifite', 'kismet', 'pixiewps',
            'reaver', 'bully', 'fern-wifi-cracker',
            'airgeddon', 'wifiphisher',

            // Reverse Engineering
            'gdb', 'radare2', 'ida-free', 'ghidra',
            'apktool', 'dex2jar', 'jd-gui',

            // Exploitation Tools
            'metasploit', 'msfconsole', 'searchsploit',
            'beef-xss', 'set', 'routersploit', 'armitage',

            // Sniffing & Spoofing
            'wireshark', 'tcpdump', 'ettercap', 'dsniff',
            'netsniff-ng', 'responder', 'bettercap', 'scapy',

            // Post Exploitation
            'empire', 'weevely', 'powersploit', 'mimikatz',
            'proxychains', 'veil', 'shellter',

            // Forensics Tools
            'autopsy', 'binwalk', 'foremost', 'volatility',
            'scalpel', 'sleuthkit', 'bulk_extractor',

            // Reporting Tools
            'maltego', 'dradis', 'faraday', 'pipal',
            'metagoofil', 'casefile'
        ];

        // Get the base command (first word)
        const baseCommand = command.split(' ')[0];
        
        // Check if it's a known command or if it exists in PATH
        return systemCommands.includes(baseCommand) || 
               this.checkCommandExists(baseCommand);
    }

    static async checkCommandExists(command) {
        try {
            await execPromise(`which ${command}`);
            return true;
        } catch {
            return false;
        }
    }

    static splitOutput(output, maxChunkSize = 4000) {
        const lines = output.split('\n');
        const chunks = [];
        let currentChunk = [];
        let currentSize = 0;

        for (const line of lines) {
            if (currentSize + line.length > maxChunkSize && currentChunk.length > 0) {
                chunks.push(currentChunk.join('\n'));
                currentChunk = [];
                currentSize = 0;
            }
            currentChunk.push(line);
            currentSize += line.length;
        }

        if (currentChunk.length > 0) {
            chunks.push(currentChunk.join('\n'));
        }

        return chunks;
    }

    static async analyzeChunk(chunk, command, apiKey, chunkIndex, totalChunks) {
        if (!chunk || !command || !apiKey) {
            throw new Error('Missing required parameters for chunk analysis');
        }

        // Skip empty chunks
        if (!chunk.trim()) {
            return null;
        }

        const context = `
        This is part ${chunkIndex + 1} of ${totalChunks} from the command output.
        
        Command: ${command}
        Output Chunk:
        ${chunk}

        Please analyze this portion of the output and provide:
        1. Security implications from this section
        2. Potential risks or vulnerabilities identified
        3. Recommended security measures based on findings
        4. Related security tools or commands for further investigation
        5. Notable patterns or indicators in this section
        `;

        try {
            const analysis = await analyzeWithMistral(apiKey, context);
            if (!analysis || analysis.error) {
                throw new Error('Analysis failed for this chunk');
            }
            return analysis;
        } catch (error) {
            console.error(colors.error(`\nError analyzing chunk ${chunkIndex + 1}:`), colors.errorOutput(error.message));
            return null;
        }
    }

    static async consolidateAnalysis(analyses, command, apiKey) {
        if (!analyses || !analyses.length || !command || !apiKey) {
            throw new Error('Missing required parameters for analysis consolidation');
        }

        const consolidationContext = `
        Please consolidate the following security analyses into a comprehensive summary.
        These analyses are from different parts of the output of command: ${command}

        Individual Analyses:
        ${analyses.map((a, i) => `
        Part ${i + 1}:
        ${a.analysis}
        `).join('\n')}

        Please provide:
        1. Overall security assessment
        2. Key findings across all sections
        3. Critical vulnerabilities or risks identified
        4. Comprehensive recommendations
        5. Suggested next steps for investigation
        `;

        try {
            return await analyzeWithMistral(apiKey, consolidationContext);
        } catch (error) {
            console.error(colors.error('Error consolidating analyses:'), colors.errorOutput(error.message));
            return {
                analysis: `Error consolidating analyses: ${error.message}`,
                timestamp: new Date().toISOString()
            };
        }
    }

    static async executeWithAnalysis(command, apiKey, driver) {
        if (!command || !apiKey || !driver) {
            throw new Error('Missing required parameters: command, apiKey, and driver are required');
        }

        // Special handling for search command
        if (command.startsWith('search')) {
            try {
                // Check if searchsploit is installed
                try {
                    await execPromise('which searchsploit');
                } catch {
                    console.log(colors.warning('\nSearchsploit not found. Installing required tools...'));
                    try {
                        await execPromise('sudo apt-get update && sudo apt-get install -y exploitdb');
                        console.log(colors.success('✓ Searchsploit installed successfully'));
                    } catch (installError) {
                        console.log(colors.warning('Failed to install searchsploit. Continuing with web-based search...'));
                    }
                }

                const searchQuery = command.replace(/^search\s*:?\s*/, '').trim();
                if (!searchQuery) {
                    console.error(colors.error('\n❌ Error: Search query is required'));
                    return { success: false, error: 'Search query is required' };
                }

                console.log(colors.info('\n🔍 Searching across multiple sources...'));
                console.log(colors.info('----------------------------------------'));

                const results = [];

                // Parallel search execution
                const searchPromises = [
                    // Web searches
                    SearchCommands.searchGoogle(searchQuery),
                    SearchCommands.searchDuckDuckGo(searchQuery),
                    SearchCommands.searchWikipedia(searchQuery),
                    
                    // Security-specific searches
                    SearchCommands.searchExploitDB(searchQuery),
                    SearchCommands.searchCVE(searchQuery),
                    SearchCommands.searchSecurityBlogs(searchQuery)
                ];

                const searchResults = await Promise.allSettled(searchPromises);
                
                // Process results
                searchResults.forEach(result => {
                    if (result.status === 'fulfilled' && result.value.success) {
                        results.push(result.value);
                        console.log(colors.success(`✓ ${result.value.platform} search complete`));
                    }
                });

                // Format and display results
                results.forEach(result => {
                    console.log(SearchCommands.formatSearchResults(result));
                });

                // Analyze results with Mistral AI
                if (results.length > 0) {
                    const searchAnalysis = await SearchCommands.analyzeSearchResults(results, searchQuery);
                    const analysis = await analyzeWithMistral(apiKey, searchAnalysis);

                    console.log(colors.header('\n📊 AI Analysis'));
                    console.log(colors.info('----------------------------------------'));
                    console.log(colors.analysis(analysis.analysis));

                    // Store in Neo4j
                    await storeInNeo4j(driver, {
                        type: 'search',
                        query: searchQuery,
                        results: results,
                        analysis: analysis.analysis,
                        timestamp: new Date().toISOString()
                    });
                }

                return { success: true, results };

            } catch (error) {
                console.error(colors.error('\n❌ Search Error:'), colors.errorOutput(error.message));
                return { success: false, error: error.message };
            }
        }

        // Add new handling for visit command
        if (command.startsWith('visit')) {
            try {
                const url = command.replace(/^visit\s*/, '').trim();
                if (!url) {
                    console.error(colors.error('\n❌ Error: URL is required'));
                    return { success: false, error: 'URL is required' };
                }

                console.log(colors.info('\n🔍 Analyzing website content...'));
                const results = await SearchCommands.visitWebsite(url, 2); // Depth of 2

                if (results.success) {
                    console.log(SearchCommands.formatWebsiteResults(results));

                    // Analyze with Mistral AI
                    const analysis = await analyzeWithMistral(
                        apiKey,
                        await SearchCommands.analyzeWebsiteContent(results.results, url)
                    );

                    console.log(colors.header('\n📊 AI Analysis'));
                    console.log(colors.info('----------------------------------------'));
                    console.log(colors.analysis(analysis.analysis));

                    // Store in Neo4j
                    await storeInNeo4j(driver, {
                        type: 'website_analysis',
                        url: url,
                        results: results.results,
                        analysis: analysis.analysis,
                        timestamp: new Date().toISOString()
                    });
                }

                return results;
            } catch (error) {
                console.error(colors.error('\n❌ Website Analysis Error:'), colors.errorOutput(error.message));
                return { success: false, error: error.message };
            }
        }

        // Add to the command handling section
        if (command.startsWith('debug')) {
            try {
                const args = command.split(' ');
                if (args.length < 2) {
                    console.error(colors.error('\n❌ Error: Specify what to debug'));
                    return { success: false, error: 'Invalid debug command' };
                }

                const target = args[1];
                
                if (target === 'code') {
                    // Analyze entire codebase
                    const analysis = await CodeAnalyzer.analyzeCodebase(apiKey);
                    
                    if (analysis) {
                        console.log(colors.header('\n📊 Code Analysis Results'));
                        console.log(colors.info('----------------------------------------'));
                        
                        for (const [file, result] of Object.entries(analysis)) {
                            console.log(colors.highlight(`\n${file}:`));
                            console.log(colors.analysis(JSON.stringify(result, null, 2)));

                            if (result.fixes && result.fixes.length > 0) {
                                const shouldApply = await question(colors.prompt(
                                    '\nApply suggested fixes? (y/n): '
                                ));

                                if (shouldApply.toLowerCase() === 'y') {
                                    await CodeAnalyzer.applyCodeFix(file, result.fixes, apiKey);
                                }
                            }
                        }
                    }
                } else if (target === 'function') {
                    // Debug specific function
                    const functionName = args[2];
                    if (!functionName) {
                        console.error(colors.error('\n❌ Error: Specify function name'));
                        return { success: false, error: 'Function name required' };
                    }

                    const testCases = [
                        { input: 'test input 1', expectedOutput: 'expected output 1' },
                        { input: 'test input 2', expectedOutput: 'expected output 2' }
                    ];

                    await CodeAnalyzer.debugFunction(functionName, testCases, apiKey);
                }

                return { success: true };
            } catch (error) {
                console.error(colors.error('\n❌ Debug Error:'), colors.errorOutput(error.message));
                return { success: false, error: error.message };
            }
        }

        // Handle other commands as before...
        console.log(colors.command(`\n📎 Executing: ${command}`));
        const result = await this.executeCommand(command);
        
        if (result.success) {
            if (result.output) {
                console.log(colors.info('\nCommand Output:'));
                console.log(colors.commandOutput(result.output));
            }
            if (result.error) {
                console.log(colors.warning('\nCommand Warnings:'));
                console.log(colors.errorOutput(result.error));
            }

            try {
                // Split large output into chunks
                const chunks = this.splitOutput(result.output || '');
                console.log(colors.info(`\nAnalyzing output in ${chunks.length} parts...`));

                // Analyze each chunk
                const chunkAnalyses = [];
                for (let i = 0; i < chunks.length; i++) {
                    if (!chunks[i].trim()) continue; // Skip empty chunks

                    console.log(colors.info(`\nAnalyzing part ${i + 1}/${chunks.length}...`));
                    const analysis = await this.analyzeChunk(
                        chunks[i],
                        command,
                        apiKey,
                        i,
                        chunks.length
                    );
                    if (analysis && !analysis.error) {
                        chunkAnalyses.push(analysis);
                    }
                }

                if (chunkAnalyses.length === 0) {
                    console.log(colors.warning('\nNo analyzable content found in the output.'));
                    return result;
                }

                // Show intermediate analysis if multiple chunks
                if (chunks.length > 1) {
                    chunkAnalyses.forEach((analysis, index) => {
                        console.log(colors.header(`\n📊 Analysis Part ${index + 1}`));
                        console.log(colors.info('----------------------------------------'));
                        console.log(colors.analysis(analysis.analysis));
                    });
                }

                // Consolidate analyses if multiple chunks
                const finalAnalysis = chunks.length > 1 
                    ? await this.consolidateAnalysis(chunkAnalyses, command, apiKey)
                    : chunkAnalyses[0];

                if (finalAnalysis && !finalAnalysis.error) {
                    console.log(colors.header('\n📊 Final Analysis'));
                    console.log(colors.info('----------------------------------------'));
                    console.log(colors.analysis(finalAnalysis.analysis));

                    // Store in Neo4j
                    await storeInNeo4j(driver, {
                        type: 'command',
                        command: command,
                        output: result.output,
                        error: result.error,
                        analysis: finalAnalysis.analysis,
                        chunkAnalyses: chunks.length > 1 ? chunkAnalyses.map(a => a.analysis) : [],
                        timestamp: new Date().toISOString()
                    });

                    // Get next steps suggestions based on valid analysis
                    const nextStepsContext = `
                    Based on the complete analysis of this command:
                    Command: ${command}
                    
                    Final Analysis:
                    ${finalAnalysis.analysis}

                    Please suggest:
                    1. Next security testing steps
                    2. Related security tools to try
                    3. Additional areas to investigate
                    4. Security checks to perform
                    5. Potential vulnerabilities to explore
                    `;

                    const nextSteps = await analyzeWithMistral(apiKey, nextStepsContext);

                    if (nextSteps && !nextSteps.error) {
                        console.log(colors.header('\n📋 Suggested Next Steps'));
                        console.log(colors.info('----------------------------------------'));
                        console.log(colors.analysis(nextSteps.analysis));
                    }
                }

            } catch (error) {
                console.error(colors.error('\nError during analysis:'), colors.errorOutput(error.message));
                console.log(colors.info('\nContinuing with basic output display...'));
            }
        } else {
            console.error(colors.error('\n❌ Error executing command:'), colors.errorOutput(result.error));
        }

        return result;
    }
}

// Add a variable to store the last command output for analysis
let lastCommandOutput = '';

async function executeCommand(command) {
    try {
        // Handle empty commands
        if (!command || command.trim() === '') {
            return true;
        }

        // Handle special commands
        const specialCommands = {
            'exit': () => {
                console.log(colors.success('\nGoodbye! 👋'));
                process.exit(0);
            },
            'clear': () => {
                console.clear();
                return true;
            },
            'help': () => {
                showHelp();
                return true;
            }
        };

        // Check for search command
        if (command.startsWith('search')) {
            const query = command.replace(/^search\s+/, '');
            await SearchCommands.executeSearch(query);
            return true;
        }

        // Handle special commands
        if (specialCommands[command]) {
            return specialCommands[command]();
        }

        // Handle hk command
        if (command.startsWith('hk')) {
            // Check root permissions first
            try {
                const userId = execSync('id -u').toString().trim();
                if (userId !== '0') {
                    console.error(colors.error('\n❌ Error: Root permissions required'));
                    console.log(colors.info('Please run the tool with sudo:'));
                    console.log(colors.command('sudo mask'));
                    return false;
                }
            } catch (error) {
                console.error(colors.error('\n❌ Error checking permissions:'), colors.errorOutput(error.message));
                return false;
            }

            const args = command.split(' ');
            if (args.length < 2) {
                console.error(colors.error('\n❌ Error: IP address required'));
                console.log(colors.info('Usage: hk <ip> [port]'));
                return false;
            }

            const ip = args[1];
            const port = args[2] || null;

            // Validate IP address
            if (!ip.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)) {
                console.error(colors.error('\n❌ Error: Invalid IP address'));
                return false;
            }

            // Validate port if provided
            if (port && (!Number.isInteger(+port) || +port < 1 || +port > 65535)) {
                console.error(colors.error('\n❌ Error: Invalid port number'));
                return false;
            }

            await HackingCommands.startHackingMode(ip, port);
            return true;
        }

        // Execute system command
        console.log(colors.command(`\n📎 Executing: ${command}`));
        const { stdout, stderr } = await execPromise(command);
        
        // Store the output for later analysis
        lastCommandOutput = stdout || stderr;
        
        // Display the output
        if (stdout) {
            console.log('\nCommand Output:');
            console.log(stdout);
        }
        
        if (stderr) {
            console.log(colors.warning('\nCommand Warnings/Errors:'));
            console.log(colors.errorOutput(stderr));
        }
        
        return true;
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.error(colors.error('\n❌ Error: Command not found'));
        } else {
            console.error(colors.error('\n❌ Error:'), colors.errorOutput(error.message));
        }
        return false;
    }
}

async function handleAnalysisCommand(command) {
    if (!lastCommandOutput) {
        console.log(colors.warning('No previous command output to analyze.'));
        return;
    }

    try {
        if (command === 'anls') {
            console.log(colors.info('\nAnalyzing last command output...'));
            const analysis = await analyzeOutput(lastCommandOutput);
            console.log(colors.header('\n📊 Analysis Results:'));
            console.log(colors.analysis(analysis));
        } else if (command === 'summary') {
            console.log(colors.info('\nGenerating summary of last command...'));
            const analysis = await analyzeOutput(lastCommandOutput, 'summary');
            console.log(colors.header('\n📝 Summary:'));
            console.log(colors.analysis(analysis));
        }
    } catch (error) {
        console.error(colors.error('\nAnalysis Error:'), colors.errorOutput(error.message));
    }
}

function showHelp() {
    console.log(colors.header('\n🎭 MASK Commands Help'));
    console.log(colors.info('----------------------------------------'));
    console.log(colors.subHeader('Analysis Commands:'));
    console.log(colors.helpCommand('anls', 'Analyze last command output'));
    console.log(colors.helpCommand('summary', 'Get brief summary of last command'));
    console.log(colors.helpCommand('search <term>', 'Search for exploits and vulnerabilities'));
    // ... add more help content
}

module.exports = {
    executeCommand,
    handleAnalysisCommand
}; 