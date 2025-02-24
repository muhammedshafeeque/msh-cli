const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const colors = require('./colors');
const { MistralAnalyzer } = require('./mistralAnalyzer');
const SearchCommands = require('./searchCommands');
const neo4j = require('neo4j-driver');
const readline = require('readline');

class HackingCommands {
    static driver = null;

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

    static async startHackingMode(ip, port = null) {
        console.log(colors.header('\n🎯 Starting Hacking Mode'));
        console.log(colors.info(`Target: ${ip}${port ? ':' + port : ''}`));
        console.log(colors.info('----------------------------------------'));

        try {
            // Initialize Neo4j driver
            this.initializeDriver();

            // Initialize Mistral Analyzer
            const analyzer = new MistralAnalyzer(process.env.MISTRAL_API_KEY);
            
            // Create readline interface for user prompts
            const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout
            });

            const askToContinue = async (message) => {
                return new Promise((resolve) => {
                    rl.question(colors.prompt(`\n⚠️ ${message} Continue? (Y/N): `), (answer) => {
                        resolve(answer.toLowerCase() === 'y');
                    });
                });
            };

            // Step 1: Information Gathering
            console.log(colors.header('\n📡 Phase 1: Information Gathering'));
            
            // Run initial quick scan
            const quickScan = await this.runQuickScan(ip, port, analyzer);
            
            // Check for sensitive information in quick scan
            const sensitiveInfo = await this.checkSensitiveInformation(quickScan, analyzer);
            if (sensitiveInfo.found) {
                console.log(colors.warning('\n⚠️ Sensitive Information Detected:'));
                console.log(colors.analysis(sensitiveInfo.details));
                
                const shouldContinue = await askToContinue('Sensitive information detected.');
                if (!shouldContinue) {
                    console.log(colors.info('\nStopping scan as requested.'));
                    rl.close();
                    return;
                }
            }

            // Comprehensive reconnaissance
            const reconResults = await this.performReconnaissance(ip, port, analyzer, rl);
            
            // Analyze vulnerabilities
            const vulnResults = await this.analyzeVulnerabilities(reconResults, analyzer);
            
            // Generate summary and next steps
            const summary = await this.generateSummary(reconResults, vulnResults, analyzer);
            
            // Display next steps
            await this.suggestNextSteps(summary, analyzer);

            rl.close();
        } catch (error) {
            console.error(colors.error('\n❌ Error in hacking mode:'), colors.errorOutput(error.message));
        } finally {
            // Close Neo4j driver if it was initialized
            if (this.driver) {
                await this.driver.close();
                this.driver = null;
            }
        }
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

    static async suggestNextSteps(summary, analyzer) {
        console.log(colors.header('\n🎯 Suggested Next Steps'));
        console.log(colors.info('----------------------------------------'));

        const nextStepsAnalysis = await analyzer.analyzeOutput(`
Based on the security assessment summary:

${JSON.stringify(summary, null, 2)}

Provide detailed next steps including:
1. Specific commands to run
2. Tools to use
3. Areas to investigate further
4. Potential attack vectors to explore
5. Additional security checks needed

Format as a structured list with commands and explanations.
`);

        console.log(colors.analysis(nextStepsAnalysis));
    }
}

module.exports = HackingCommands; 