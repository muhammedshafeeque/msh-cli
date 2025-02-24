const { exec, execSync } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const colors = require('./colors');
const { MistralAnalyzer } = require('./mistralAnalyzer');
const SearchCommands = require('./searchCommands');
const neo4j = require('neo4j-driver');
const readline = require('readline');

class HackingCommands {
    static driver = null;
    static currentTarget = null;
    static sessionHistory = [];

    static initializeDriver() {
        if (!this.driver) {
            this.driver = neo4j.driver(
                process.env.NEO4J_URI || 'bolt://localhost:7687',
                neo4j.auth.basic(
                    process.env.NEO4J_USER || 'neo4j',
                    process.env.NEO4J_PASSWORD
                )
            );
        }
        return this.driver;
    }

    static async checkRootPermissions() {
        try {
            // Check if running as root
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

    static async startHackingMode(ip, port = null) {
        try {
            // Check root permissions first
            await this.checkRootPermissions();

            console.log(colors.success('✓ Root permissions verified'));
            console.log(colors.warning('\n⚠️ Warning: This tool should only be used on authorized systems'));
            
            this.currentTarget = { ip, port };
            this.initializeDriver();
            const analyzer = new MistralAnalyzer(process.env.MISTRAL_API_KEY);
            
            const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout,
                prompt: colors.prompt('hack> ')
            });

            // Initial Information Gathering
            await this.initialRecon(ip, port, analyzer, rl);

            // Start interactive mode
            await this.startInteractiveMode(rl, analyzer);

        } catch (error) {
            console.error(colors.error('\n❌ Error:'), colors.errorOutput(error.message));
        }
    }

    static async initialRecon(ip, port, analyzer, rl) {
        console.log(colors.header('\n📡 Phase 1: Initial Reconnaissance'));
        
        // Quick scan first
        const quickScan = await this.runQuickScan(ip, port, analyzer);
        
        // Check for sensitive information
        const sensitiveInfo = await this.checkSensitiveInformation(quickScan, analyzer);
        if (sensitiveInfo.found) {
            console.log(colors.warning('\n⚠️ Sensitive Information Detected:'));
            console.log(colors.analysis(sensitiveInfo.details));
            
            const shouldContinue = await this.askQuestion(rl, 'Sensitive information detected. Continue? (Y/N): ');
            if (shouldContinue.toLowerCase() !== 'y') {
                console.log(colors.info('\nStopping scan as requested.'));
                process.exit(0);
            }
        }

        // Full reconnaissance
        await this.fullReconnaissance(ip, port, analyzer);
    }

    static async startInteractiveMode(rl, analyzer) {
        console.log(colors.header('\n🎯 Interactive Hacking Mode'));
        console.log(colors.info('----------------------------------------'));
        
        rl.prompt();

        rl.on('line', async (line) => {
            const command = line.trim();

            if (command === 'end') {
                console.log(colors.success('\nGenerating final session summary...'));
                await this.displaySessionSummary();
                console.log(colors.success('\nExiting hacking mode...'));
                rl.close();
                return;
            }

            if (command === 'summary') {
                await this.displaySessionSummary();
                rl.prompt();
                return;
            }

            try {
                // Store command in session history
                this.sessionHistory.push({
                    command,
                    timestamp: new Date().toISOString()
                });

                // Analyze command in context
                const commandAnalysis = await this.analyzeCommandInContext(command, analyzer);
                
                // Display command analysis
                console.log(colors.header('\n🔍 Command Analysis'));
                console.log(colors.info('----------------------------------------'));
                console.log(colors.analysis(commandAnalysis.analysis));
                
                if (commandAnalysis.warning) {
                    const proceed = await this.askQuestion(rl, `⚠️ ${commandAnalysis.warning}\nProceed? (Y/N): `);
                    if (proceed.toLowerCase() !== 'y') {
                        console.log(colors.info('Command aborted.'));
                        rl.prompt();
                        return;
                    }
                }

                // Execute command
                const result = await this.executeCommand(command);
                
                // Analyze results
                const analysis = await this.analyzeResults(result, analyzer);
                
                // Store results in Neo4j
                await this.storeCommandResults(command, result, analysis);
                
                // Show next steps
                await this.suggestNextSteps(analysis, analyzer);

            } catch (error) {
                console.error(colors.error('\n❌ Error:'), colors.errorOutput(error.message));
            }

            rl.prompt();
        });

        rl.on('close', () => {
            console.log(colors.success('\nHacking session ended.'));
            process.exit(0);
        });
    }

    static async analyzeCommandInContext(command, analyzer) {
        const context = {
            target: this.currentTarget,
            history: this.sessionHistory,
            command: command
        };

        const analysis = await analyzer.analyzeOutput(`
Analyze this command in the context of the current hacking session:

Target: ${JSON.stringify(this.currentTarget)}
Command History: ${JSON.stringify(this.sessionHistory)}
Current Command: ${command}

Provide:
1. Command safety assessment
2. Potential risks
3. Expected outcomes
4. Warning messages if necessary
5. Suggested modifications if needed

Return as JSON:
{
    "safe": boolean,
    "warning": string or null,
    "analysis": string,
    "suggestions": string[]
}
`);

        try {
            return JSON.parse(analysis);
        } catch (error) {
            return {
                safe: false,
                warning: "Could not analyze command safety",
                analysis: "",
                suggestions: []
            };
        }
    }

    static async executeCommand(command) {
        console.log(colors.command(`\n📎 Executing: ${command}`));
        
        try {
            const { stdout, stderr } = await execPromise(command);
            
            // Display command output
            if (stdout) {
                console.log(colors.info('\nCommand Output:'));
                console.log(colors.commandOutput(stdout));
            }
            
            if (stderr) {
                console.log(colors.warning('\nCommand Warnings/Errors:'));
                console.log(colors.errorOutput(stderr));
            }

            return {
                success: true,
                output: stdout,
                error: stderr,
                command: command
            };
        } catch (error) {
            console.error(colors.error('\nCommand execution failed:'), colors.errorOutput(error.message));
            return {
                success: false,
                output: '',
                error: error.message,
                command: command
            };
        }
    }

    static async analyzeResults(results, analyzer) {
        console.log(colors.header('\n📊 Analysis in Progress...'));
        
        const analysis = await analyzer.analyzeOutput(`
Analyze these command results in the context of the current target:

Target: ${JSON.stringify(this.currentTarget)}
Results: ${JSON.stringify(results)}

Provide a detailed analysis including:
1. Key Findings:
   - Discovered services
   - Open ports
   - Vulnerabilities
   - Security issues

2. Security Implications:
   - Risk assessment
   - Potential threats
   - Attack vectors

3. Technical Details:
   - Service versions
   - System information
   - Configuration issues

4. Recommendations:
   - Security measures
   - Further investigation
   - Mitigation steps

Format the response in a clear, structured manner with sections and bullet points.
`);

        // Display analysis results
        console.log(colors.header('\n📊 Analysis Results'));
        console.log(colors.info('----------------------------------------'));
        console.log(colors.analysis(analysis));

        return analysis;
    }

    static async suggestNextSteps(analysis, analyzer) {
        console.log(colors.header('\n📋 Suggested Next Steps'));
        console.log(colors.info('----------------------------------------'));

        const suggestions = await analyzer.analyzeOutput(`
Based on the current analysis and session history:

${analysis}

Suggest next steps including:
1. Specific commands to try
2. Areas to investigate
3. Potential vulnerabilities to exploit
4. Security checks to perform
5. Tools to use

Format as a numbered list with explanations.
`);

        console.log(colors.analysis(suggestions));
    }

    static async runQuickScan(ip, port, analyzer) {
        console.log(colors.info('\n🔍 Running Quick Initial Scan...'));
        
        const quickScanCmd = `nmap -T4 -F ${ip}${port ? ' -p ' + port : ''}`;
        try {
            const { stdout } = await execPromise(quickScanCmd);
            
            // Analyze quick scan results
            const analysis = await analyzer.analyzeOutput(`
Analyze this quick scan result for immediate security concerns:

${stdout}

Look for:
1. Obvious vulnerabilities
2. Sensitive services
3. Critical open ports
4. Immediate security risks
5. Exposed sensitive information
`);

            return {
                output: stdout,
                analysis
            };
        } catch (error) {
            console.error(colors.error('Quick scan failed:'), error.message);
            return { output: '', analysis: '' };
        }
    }

    static async checkSensitiveInformation(scanResult, analyzer) {
        const sensitiveAnalysis = await analyzer.analyzeOutput(`
Analyze this scan result for sensitive information exposure:

${JSON.stringify(scanResult, null, 2)}

Look specifically for:
1. Exposed administrative interfaces
2. Default credentials
3. Sensitive service versions
4. Critical security misconfigurations
5. Exposed internal information

Return a JSON object with:
{
    "found": boolean,
    "details": string (description of findings),
    "severity": "Critical"|"High"|"Medium"|"Low",
    "recommendations": string[]
}
`);

        try {
            return JSON.parse(sensitiveAnalysis);
        } catch (error) {
            return {
                found: false,
                details: "Error analyzing sensitive information",
                severity: "Unknown",
                recommendations: []
            };
        }
    }

    static async performReconnaissance(ip, port, analyzer, rl) {
        console.log(colors.header('\n📡 Phase 1: Information Gathering'));
        
        const scanResults = {
            nmap: await this.runNmapScans(ip, port, analyzer),
            dns: await this.runDNSEnumeration(ip, analyzer),
            service: await this.runServiceDetection(ip, port, analyzer),
            os: await this.runOSFingerprinting(ip, analyzer)
        };

        // Analyze overall reconnaissance results
        console.log(colors.info('\n🔍 Analyzing reconnaissance results...'));
        const reconAnalysis = await analyzer.analyzeOutput(`
Analyze these reconnaissance results for ${ip}:

Nmap Results:
${JSON.stringify(scanResults.nmap, null, 2)}

DNS Enumeration:
${JSON.stringify(scanResults.dns, null, 2)}

Service Detection:
${JSON.stringify(scanResults.service, null, 2)}

OS Fingerprinting:
${JSON.stringify(scanResults.os, null, 2)}

Provide a detailed analysis including:
1. Discovered attack surface
2. Potential entry points
3. Service vulnerabilities
4. System weaknesses
5. Recommended next steps
`);

        // Store results in Neo4j
        await this.storeReconResults(ip, scanResults, reconAnalysis);

        return {
            scanResults,
            analysis: reconAnalysis
        };
    }

    static async runNmapScans(ip, port, analyzer) {
        const nmapScans = [
            {
                name: 'Quick Scan',
                cmd: `nmap -T4 -F ${ip}${port ? ' -p ' + port : ''}`,
            },
            {
                name: 'Version Detection',
                cmd: `nmap -sV -sC ${ip}${port ? ' -p ' + port : ''}`,
            },
            {
                name: 'All Ports',
                cmd: `nmap -p- ${ip}`,
            },
            {
                name: 'UDP Scan',
                cmd: `nmap -sU --top-ports 100 ${ip}`,
            },
            {
                name: 'Vulnerability Scan',
                cmd: `nmap --script vuln ${ip}${port ? ' -p ' + port : ''}`,
            }
        ];

        const results = {};
        
        for (const scan of nmapScans) {
            console.log(colors.info(`\n🔍 Running ${scan.name}...`));
            try {
                const { stdout } = await execPromise(scan.cmd);
                results[scan.name] = stdout;
                console.log(colors.success(`✓ ${scan.name} completed`));
                console.log(colors.commandOutput(stdout));

                // Analyze each scan result
                const analysis = await analyzer.analyzeOutput(`
Analyze this ${scan.name} result for security implications:

${stdout}

Provide:
1. Key findings
2. Potential vulnerabilities
3. Security risks
4. Recommended actions
`);
                
                results[scan.name + '_analysis'] = analysis;
                console.log(colors.analysis('\nAnalysis:'));
                console.log(colors.analysis(analysis));

            } catch (error) {
                console.log(colors.warning(`⚠ ${scan.name} failed: ${error.message}`));
                results[scan.name] = `Error: ${error.message}`;
            }
        }

        return results;
    }

    static async runDNSEnumeration(ip, analyzer) {
        const dnsTools = [
            {
                name: 'DNSenum',
                cmd: `dnsenum ${ip}`
            },
            {
                name: 'DNSrecon',
                cmd: `dnsrecon -d ${ip}`
            },
            {
                name: 'Fierce',
                cmd: `fierce --domain ${ip}`
            }
        ];

        const results = {};

        for (const tool of dnsTools) {
            console.log(colors.info(`\n🔍 Running ${tool.name}...`));
            try {
                const { stdout } = await execPromise(tool.cmd);
                results[tool.name] = stdout;
                console.log(colors.success(`✓ ${tool.name} completed`));
                console.log(colors.commandOutput(stdout));

                // Analyze DNS enumeration result
                const analysis = await analyzer.analyzeOutput(`
Analyze this ${tool.name} result for security implications:

${stdout}

Provide:
1. Key findings
2. Potential vulnerabilities
3. Security risks
4. Recommended actions
`);
                
                results[tool.name + '_analysis'] = analysis;
                console.log(colors.analysis('\nAnalysis:'));
                console.log(colors.analysis(analysis));

            } catch (error) {
                console.log(colors.warning(`⚠ ${tool.name} failed: ${error.message}`));
                results[tool.name] = `Error: ${error.message}`;
            }
        }

        return results;
    }

    static async runServiceDetection(ip, port, analyzer) {
        const serviceTools = [
            {
                name: 'WhatWeb',
                cmd: `whatweb ${ip}${port ? ':' + port : ''}`
            },
            {
                name: 'Banner Grab',
                cmd: `nc -v -n -z -w1 ${ip} ${port || '80'}`
            }
        ];

        const results = {};

        for (const tool of serviceTools) {
            console.log(colors.info(`\n🔍 Running ${tool.name}...`));
            try {
                const { stdout } = await execPromise(tool.cmd);
                results[tool.name] = stdout;
                console.log(colors.success(`✓ ${tool.name} completed`));
                console.log(colors.commandOutput(stdout));

                // Analyze service detection result
                const analysis = await analyzer.analyzeOutput(`
Analyze this ${tool.name} result for security implications:

${stdout}

Provide:
1. Key findings
2. Potential vulnerabilities
3. Security risks
4. Recommended actions
`);
                
                results[tool.name + '_analysis'] = analysis;
                console.log(colors.analysis('\nAnalysis:'));
                console.log(colors.analysis(analysis));

            } catch (error) {
                console.log(colors.warning(`⚠ ${tool.name} failed: ${error.message}`));
                results[tool.name] = `Error: ${error.message}`;
            }
        }

        return results;
    }

    static async runOSFingerprinting(ip, analyzer) {
        const osTools = [
            {
                name: 'OS Detection',
                cmd: `nmap -O ${ip}`
            }
        ];

        const results = {};

        for (const tool of osTools) {
            console.log(colors.info(`\n🔍 Running ${tool.name}...`));
            try {
                const { stdout } = await execPromise(tool.cmd);
                results[tool.name] = stdout;
                console.log(colors.success(`✓ ${tool.name} completed`));
                console.log(colors.commandOutput(stdout));

                // Analyze OS fingerprinting result
                const analysis = await analyzer.analyzeOutput(`
Analyze this ${tool.name} result for security implications:

${stdout}

Provide:
1. Key findings
2. Potential vulnerabilities
3. Security risks
4. Recommended actions
`);
                
                results[tool.name + '_analysis'] = analysis;
                console.log(colors.analysis('\nAnalysis:'));
                console.log(colors.analysis(analysis));

            } catch (error) {
                console.log(colors.warning(`⚠ ${tool.name} failed: ${error.message}`));
                results[tool.name] = `Error: ${error.message}`;
            }
        }

        return results;
    }

    static async storeReconResults(ip, results, analysis) {
        if (!this.driver) {
            console.log(colors.warning('Neo4j driver not initialized, skipping storage'));
            return;
        }

        const session = this.driver.session();
        try {
            await session.run(
                `
                MERGE (host:Host {ip: $ip})
                WITH host
                UNWIND $results as result
                CREATE (scan:Scan {
                    type: result.type,
                    output: result.output,
                    analysis: result.analysis,
                    timestamp: datetime()
                })
                CREATE (host)-[:HAS_SCAN]->(scan)
                `,
                { 
                    ip, 
                    results: Object.entries(results).map(([type, output]) => ({
                        type,
                        output: typeof output === 'string' ? output : JSON.stringify(output),
                        analysis: results[type + '_analysis'] || ''
                    }))
                }
            );

            // Store the overall analysis
            await session.run(
                `
                MERGE (host:Host {ip: $ip})
                CREATE (analysis:Analysis {
                    type: 'Reconnaissance',
                    content: $analysis,
                    timestamp: datetime()
                })
                CREATE (host)-[:HAS_ANALYSIS]->(analysis)
                `,
                { ip, analysis }
            );
        } catch (error) {
            console.error(colors.error('Error storing results in Neo4j:'), error.message);
        } finally {
            await session.close();
        }
    }

    static async analyzeVulnerabilities(reconResults, analyzer) {
        console.log(colors.header('\n🔍 Phase 2: Vulnerability Analysis'));
        
        // Extract and analyze vulnerabilities from scan results
        const vulnerabilities = await this.extractVulnerabilities(reconResults, analyzer);
        
        // Search for exploits and analyze findings
        const exploitResults = [];
        for (const vuln of vulnerabilities) {
            const exploitInfo = await this.searchExploits(vuln);
            exploitResults.push(exploitInfo);
        }

        // Comprehensive vulnerability analysis
        const vulnAnalysis = await analyzer.analyzeOutput(`
Analyze these vulnerability findings:

Identified Vulnerabilities:
${JSON.stringify(vulnerabilities, null, 2)}

Available Exploits:
${JSON.stringify(exploitResults, null, 2)}

Provide a detailed security assessment including:
1. Critical vulnerabilities
2. Exploit possibilities
3. Risk levels
4. Attack vectors
5. Mitigation strategies
`);

        return {
            vulnerabilities,
            exploits: exploitResults,
            analysis: vulnAnalysis
        };
    }

    static async extractVulnerabilities(reconResults, analyzer) {
        const vulnAnalysis = await analyzer.analyzeOutput(`
Extract and categorize vulnerabilities from these reconnaissance results:

${JSON.stringify(reconResults, null, 2)}

Format the response as a JSON array of vulnerability objects with:
1. name
2. description
3. severity (Critical/High/Medium/Low)
4. affected_component
5. potential_impact
`);

        try {
            return JSON.parse(vulnAnalysis);
        } catch (error) {
            console.error(colors.error('Error parsing vulnerability analysis:'), error);
            return [];
        }
    }

    static async searchExploits(vulnerability) {
        // Search for exploits using SearchCommands
        await SearchCommands.executeSearch(vulnerability.name);
    }

    static async generateSummary(reconResults, vulnResults, analyzer) {
        console.log(colors.header('\n📊 Phase 3: Summary Generation'));
        
        // Generate comprehensive summary
        const summaryAnalysis = await analyzer.analyzeOutput(`
Create a comprehensive security assessment summary:

Reconnaissance Results:
${JSON.stringify(reconResults, null, 2)}

Vulnerability Analysis:
${JSON.stringify(vulnResults, null, 2)}

Provide a detailed report including:
1. Executive Summary
2. Critical Findings
3. Risk Assessment
4. Technical Details
5. Recommendations
6. Suggested Tools/Commands for Further Investigation
`);

        const summary = {
            timestamp: new Date().toISOString(),
            reconResults,
            vulnResults,
            analysis: summaryAnalysis
        };

        // Store summary in Neo4j
        await this.storeSummary(summary);

        // Display summary
        this.displaySummary(summary);

        return summary;
    }

    static async storeSummary(summary) {
        if (!this.driver) {
            console.log(colors.warning('Neo4j driver not initialized, skipping storage'));
            return;
        }

        const session = this.driver.session();
        try {
            await session.run(`
                MERGE (host:Host {ip: $ip})
                CREATE (sum:Summary {
                    timestamp: datetime(),
                    analysis: $analysis,
                    reconResults: $reconResults,
                    vulnResults: $vulnResults
                })
                CREATE (host)-[:HAS_SUMMARY]->(sum)
            `, {
                ip: summary.reconResults.scanResults.ip || summary.reconResults.ip,
                analysis: summary.analysis,
                reconResults: JSON.stringify(summary.reconResults),
                vulnResults: JSON.stringify(summary.vulnResults)
            });
        } catch (error) {
            console.error(colors.error('Error storing summary in Neo4j:'), error.message);
        } finally {
            await session.close();
        }
    }

    static displaySummary(summary) {
        console.log(colors.header('\n📝 Security Assessment Summary'));
        console.log(colors.info('----------------------------------------'));
        console.log(colors.analysis(summary.analysis));
        
        // Display additional sections if needed
        if (summary.vulnResults?.vulnerabilities?.length > 0) {
            console.log(colors.header('\n🔒 Critical Vulnerabilities'));
            console.log(colors.info('----------------------------------------'));
            summary.vulnResults.vulnerabilities
                .filter(v => v.severity === 'Critical')
                .forEach(v => {
                    console.log(colors.critical(`\n${v.name}`));
                    console.log(colors.analysis(v.description));
                });
        }
    }

    static async askQuestion(rl, question) {
        return new Promise((resolve) => {
            rl.question(question, (answer) => {
                resolve(answer);
            });
        });
    }

    static async storeCommandResults(command, result, analysis) {
        if (!this.driver) {
            console.log(colors.warning('Neo4j driver not initialized, skipping storage'));
            return;
        }

        const session = this.driver.session();
        try {
            await session.run(`
                MERGE (host:Host {ip: $ip})
                CREATE (cmd:Command {
                    command: $command,
                    result: $result,
                    analysis: $analysis,
                    timestamp: datetime()
                })
                CREATE (host)-[:HAS_COMMAND]->(cmd)
            `, {
                ip: this.currentTarget.ip,
                command,
                result,
                analysis
            });
        } catch (error) {
            console.error(colors.error('Error storing command results in Neo4j:'), error.message);
        } finally {
            await session.close();
        }
    }

    static async displaySessionSummary() {
        console.log(colors.header('\n📑 Session Summary'));
        console.log(colors.info('----------------------------------------'));

        // Display target information
        console.log(colors.subHeader('\nTarget Information:'));
        console.log(colors.info(`IP: ${this.currentTarget.ip}`));
        if (this.currentTarget.port) {
            console.log(colors.info(`Port: ${this.currentTarget.port}`));
        }

        // Display command history
        console.log(colors.subHeader('\nCommand History:'));
        this.sessionHistory.forEach((entry, index) => {
            console.log(colors.commandOutput(`${index + 1}. ${entry.command} (${new Date(entry.timestamp).toLocaleTimeString()})`));
        });

        // Get session summary from Neo4j
        const summary = await this.getSessionSummary();
        if (summary) {
            console.log(colors.subHeader('\nKey Findings:'));
            console.log(colors.analysis(summary));
        }
    }

    static async getSessionSummary() {
        if (!this.driver) return null;

        const session = this.driver.session();
        try {
            const result = await session.run(`
                MATCH (host:Host {ip: $ip})-[:HAS_COMMAND]->(cmd:Command)
                RETURN collect(cmd) as commands
            `, { ip: this.currentTarget.ip });

            const commands = result.records[0].get('commands');
            
            // Analyze all command results together
            const analyzer = new MistralAnalyzer(process.env.MISTRAL_API_KEY);
            const summary = await analyzer.analyzeOutput(`
Analyze this complete hacking session:

Target: ${JSON.stringify(this.currentTarget)}
Commands and Results:
${JSON.stringify(commands, null, 2)}

Provide a comprehensive summary including:
1. Overall Attack Surface
2. Critical Vulnerabilities
3. Key Security Findings
4. Successful Exploits
5. Recommended Next Steps

Format the response in a clear, structured manner.
`);

            return summary;
        } catch (error) {
            console.error(colors.error('Error getting session summary:'), error.message);
            return null;
        } finally {
            await session.close();
        }
    }

    static async fullReconnaissance(ip, port, analyzer) {
        console.log(colors.header('\n🔍 Starting Full Reconnaissance'));
        console.log(colors.info('----------------------------------------'));

        const reconResults = {};

        // 1. Network Scanning & Reconnaissance
        console.log(colors.subHeader('\n1. Network Scanning'));
        reconResults.network = await this.runNetworkScans(ip, port, analyzer);

        // 2. DNS & Subdomain Enumeration
        console.log(colors.subHeader('\n2. DNS Enumeration'));
        reconResults.dns = await this.runDNSEnumeration(ip, analyzer);

        // 3. Whois & IP Lookup
        console.log(colors.subHeader('\n3. Whois Information'));
        reconResults.whois = await this.runWhoisLookup(ip, analyzer);

        // 4. OS & Service Fingerprinting
        console.log(colors.subHeader('\n4. Service Detection'));
        reconResults.services = await this.runServiceDetection(ip, port, analyzer);

        // 5. Banner Grabbing & Web Recon
        console.log(colors.subHeader('\n5. Web Reconnaissance'));
        reconResults.web = await this.runWebRecon(ip, port, analyzer);

        // Replace the simple analysis with comprehensive analysis
        const analysis = await this.generateComprehensiveAnalysis(reconResults, analyzer);

        return {
            results: reconResults,
            analysis
        };
    }

    static async runNetworkScans(ip, port, analyzer) {
        const scans = [
            {
                name: 'Nmap Comprehensive',
                cmd: `nmap -sC -sV -O -A ${ip}${port ? ' -p ' + port : ''}`
            },
            {
                name: 'Masscan Quick',
                cmd: `masscan ${ip} -p1-65535 --rate=1000`
            },

            {
                name: 'Unicornscan',
                cmd: `unicornscan ${ip}`
            },
            {
                name: 'Hping3 Scan',
                cmd: `hping3 -8 1-65535 ${ip}`
            }
        ];

        const results = {};
        for (const scan of scans) {
            try {
                console.log(colors.info(`\nRunning ${scan.name}...`));
                const { stdout } = await execPromise(scan.cmd);
                results[scan.name] = stdout;
                
                // Analyze each scan result
                const analysis = await analyzer.analyzeOutput(`
Analyze this ${scan.name} result:

${stdout}

Provide key findings and security implications.
`);
                results[scan.name + '_analysis'] = analysis;
                
                console.log(colors.success(`✓ ${scan.name} completed`));
                console.log(colors.analysis(analysis));
            } catch (error) {
                console.log(colors.warning(`⚠ ${scan.name} failed: ${error.message}`));
                results[scan.name] = `Error: ${error.message}`;
            }
        }
        return results;
    }

    static async runWhoisLookup(ip, analyzer) {
        const tools = [
            {
                name: 'Whois',
                cmd: `whois ${ip}`
            },
            {
                name: 'TheHarvester',
                cmd: `theHarvester -d ${ip} -b all`
            }
        ];

        const results = {};
        for (const tool of tools) {
            try {
                console.log(colors.info(`\nRunning ${tool.name}...`));
                const { stdout } = await execPromise(tool.cmd);
                results[tool.name] = stdout;
                
                const analysis = await analyzer.analyzeOutput(`
Analyze this ${tool.name} result:

${stdout}

Identify any sensitive or useful information.
`);
                results[tool.name + '_analysis'] = analysis;
                
                console.log(colors.success(`✓ ${tool.name} completed`));
                console.log(colors.analysis(analysis));
            } catch (error) {
                console.log(colors.warning(`⚠ ${tool.name} failed: ${error.message}`));
                results[tool.name] = `Error: ${error.message}`;
            }
        }
        return results;
    }

    static async runWebRecon(ip, port, analyzer) {
        const tools = [
            {
                name: 'WhatWeb',
                cmd: `whatweb ${ip}${port ? ':' + port : ''}`
            },
            {
                name: 'HTTProbe',
                cmd: `httprobe ${ip}`
            },

            {
                name: 'EyeWitness',
                cmd: `eyewitness --web --single ${ip}${port ? ':' + port : ''}`
            }
        ];

        const results = {};
        for (const tool of tools) {
            try {
                console.log(colors.info(`\nRunning ${tool.name}...`));
                const { stdout } = await execPromise(tool.cmd);
                results[tool.name] = stdout;
                
                const analysis = await analyzer.analyzeOutput(`
Analyze this ${tool.name} result:

${stdout}

Identify web technologies, vulnerabilities, and security issues.
`);
                results[tool.name + '_analysis'] = analysis;
                
                console.log(colors.success(`✓ ${tool.name} completed`));
                console.log(colors.analysis(analysis));
            } catch (error) {
                console.log(colors.warning(`⚠ ${tool.name} failed: ${error.message}`));
                results[tool.name] = `Error: ${error.message}`;
            }
        }
        return results;
    }

    static async generateComprehensiveAnalysis(reconResults, analyzer) {
        console.log(colors.header('\n📊 Generating Comprehensive Analysis'));
        console.log(colors.info('----------------------------------------'));

        const results = {
            vulnerabilities: null,
            attack_strategy: null,
            exploit_info: null
        };

        // 1. Analyze vulnerabilities
        try {
            console.log(colors.info('\nAnalyzing vulnerabilities...'));
            const vulnResponse = await analyzer.analyzeOutput(`
Analyze these reconnaissance results for vulnerabilities:
${JSON.stringify(reconResults, null, 2)}

Return a JSON object in this exact format:
{
    "vulnerabilities": {
        "cves": [
            {
                "id": "CVE ID",
                "description": "Vulnerability description",
                "severity": "Critical/High/Medium/Low",
                "affected_component": "Affected service/software",
                "exploit_available": boolean,
                "exploit_links": ["ExploitDB/Github/Metasploit links"],
                "fixed_version": "Version where this is fixed",
                "patch_info": "Patch/mitigation details"
            }
        ],
        "other_issues": [
            {
                "type": "Issue type",
                "description": "Issue description",
                "severity": "Critical/High/Medium/Low"
            }
        ]
    }
}
`);

            // Validate and parse the response
            try {
                results.vulnerabilities = JSON.parse(vulnResponse);
                if (!results.vulnerabilities?.vulnerabilities?.cves) {
                    throw new Error('Invalid vulnerability analysis format');
                }
            } catch (parseError) {
                console.log(colors.warning('⚠️ Error parsing vulnerability analysis, storing as raw text'));
                results.vulnerabilities = { 
                    vulnerabilities: { 
                        cves: [], 
                        other_issues: [],
                        raw_analysis: vulnResponse 
                    } 
                };
            }
        } catch (error) {
            console.log(colors.warning('⚠️ Vulnerability analysis skipped:', error.message));
            results.vulnerabilities = { 
                vulnerabilities: { 
                    cves: [], 
                    other_issues: [],
                    error: error.message 
                } 
            };
        }

        // Wait between requests
        await new Promise(resolve => setTimeout(resolve, 2000));

        // 2. Search for exploits
        try {
            console.log(colors.info('\nSearching for exploits...'));
            results.exploit_info = await SearchCommands.executeSearch(
                reconResults.services?.['Nmap Comprehensive'] || '', 
                true
            );
        } catch (error) {
            console.log(colors.warning('⚠️ Exploit search skipped:', error.message));
            results.exploit_info = { error: error.message };
        }

        // Wait between requests
        await new Promise(resolve => setTimeout(resolve, 2000));

        // 3. Generate attack strategy
        try {
            console.log(colors.info('\nGenerating attack strategy...'));
            results.attack_strategy = await analyzer.analyzeOutput(`
Based on the reconnaissance results and findings:
${JSON.stringify(reconResults, null, 2)}

Vulnerabilities found:
${JSON.stringify(results.vulnerabilities, null, 2)}

Provide a detailed attack strategy including:
1. Potential Attack Vectors
2. Required Tools
3. Step-by-Step Commands
4. Success Probability
5. Expected Outcomes

Format as a clear, structured response.
`);
        } catch (error) {
            console.log(colors.warning('⚠️ Attack strategy generation skipped:', error.message));
            results.attack_strategy = { error: error.message };
        }

        // Display results
        console.log(colors.subHeader('\n🎯 Target Analysis'));
        console.log(colors.info('----------------------------------------'));

        // Display CVEs and Exploits
        if (results.vulnerabilities?.vulnerabilities?.cves?.length > 0) {
            console.log(colors.subHeader('\n🔒 Identified Vulnerabilities:'));
            results.vulnerabilities.vulnerabilities.cves.forEach(cve => {
                console.log(colors.critical(`\n${cve.id} - ${cve.severity}`));
                console.log(colors.info(`Component: ${cve.affected_component}`));
                console.log(colors.info(`Description: ${cve.description}`));
                if (cve.exploit_available) {
                    console.log(colors.warning('Exploits Available:'));
                    cve.exploit_links.forEach(link => {
                        console.log(colors.link(`  • ${link}`));
                    });
                }
                console.log(colors.success(`Fixed in: ${cve.fixed_version}`));
                console.log(colors.info(`Patch Info: ${cve.patch_info}`));
            });
        } else if (results.vulnerabilities?.vulnerabilities?.raw_analysis) {
            console.log(colors.subHeader('\n🔍 Vulnerability Analysis:'));
            console.log(colors.analysis(results.vulnerabilities.vulnerabilities.raw_analysis));
        }

        // Display Attack Strategy
        if (results.attack_strategy && !results.attack_strategy.error) {
            console.log(colors.subHeader('\n⚔️ Attack Strategy:'));
            console.log(colors.analysis(results.attack_strategy));
        }

        // Store results in Neo4j
        try {
            await this.storeAnalysis(reconResults, results.vulnerabilities, results.attack_strategy);
        } catch (error) {
            console.log(colors.warning('⚠️ Error storing analysis in database:', error.message));
        }

        return results;
    }

    static async storeAnalysis(reconResults, vulnAnalysis, attackStrategy) {
        if (!this.driver) return;

        const session = this.driver.session();
        try {
            await session.run(`
                MATCH (host:Host {ip: $ip})
                CREATE (analysis:Analysis {
                    timestamp: datetime(),
                    recon_results: $reconResults,
                    vulnerabilities: $vulnAnalysis,
                    attack_strategy: $attackStrategy
                })
                CREATE (host)-[:HAS_ANALYSIS]->(analysis)
            `, {
                ip: this.currentTarget.ip,
                reconResults: JSON.stringify(reconResults),
                vulnAnalysis,
                attackStrategy
            });
        } finally {
            await session.close();
        }
    }
}

module.exports = HackingCommands; module.exports = HackingCommands; 
