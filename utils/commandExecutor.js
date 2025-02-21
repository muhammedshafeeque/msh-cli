const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const colors = require('./colors');
const { analyzeWithMistral } = require('./mistralAnalyzer');
const { storeInNeo4j } = require('./neo4jHandler');

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

        return await analyzeWithMistral(apiKey, context);
    }

    static async consolidateAnalysis(analyses, command, apiKey) {
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

        return await analyzeWithMistral(apiKey, consolidationContext);
    }

    static async executeWithAnalysis(command, apiKey, driver) {
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
                const chunks = this.splitOutput(result.output);
                console.log(colors.info(`\nAnalyzing output in ${chunks.length} parts...`));

                // Analyze each chunk
                const chunkAnalyses = [];
                for (let i = 0; i < chunks.length; i++) {
                    console.log(colors.info(`\nAnalyzing part ${i + 1}/${chunks.length}...`));
                    const analysis = await this.analyzeChunk(
                        chunks[i],
                        command,
                        apiKey,
                        i,
                        chunks.length
                    );
                    chunkAnalyses.push(analysis);

                    // Show intermediate analysis if multiple chunks
                    if (chunks.length > 1) {
                        console.log(colors.header(`\n📊 Analysis Part ${i + 1}`));
                        console.log(colors.info('----------------------------------------'));
                        console.log(colors.analysis(analysis.analysis));
                    }
                }

                // Consolidate analyses if multiple chunks
                const finalAnalysis = chunks.length > 1 
                    ? await this.consolidateAnalysis(chunkAnalyses, command, apiKey)
                    : chunkAnalyses[0];

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

                // Get next steps suggestions
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

                console.log(colors.header('\n📋 Suggested Next Steps'));
                console.log(colors.info('----------------------------------------'));
                console.log(colors.analysis(nextSteps.analysis));

            } catch (error) {
                console.error(colors.error('Error during analysis:'), colors.errorOutput(error.message));
            }
        } else {
            console.error(colors.error('\n❌ Error executing command:'), colors.errorOutput(result.error));
        }

        return result;
    }
}

module.exports = CommandExecutor; 