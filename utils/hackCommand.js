const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const colors = require('./colors');
const { MistralAnalyzer } = require('./mistralAnalyzer');
const SearchCommands = require('./searchCommands');
const neo4j = require('neo4j-driver');

class HackCommand {
    constructor() {
        this.driver = neo4j.driver(
            process.env.NEO4J_URI || 'bolt://localhost:7687',
            neo4j.auth.basic(process.env.NEO4J_USER || 'neo4j', process.env.NEO4J_PASSWORD || 'password')
        );
        this.analyzer = new MistralAnalyzer(process.env.MISTRAL_API_KEY);
    }

    async validateInput(ip, port) {
        // Validate IP address format
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipRegex.test(ip)) {
            throw new Error('Invalid IP address format');
        }

        // Validate port if provided
        if (port) {
            const portNum = parseInt(port);
            if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
                throw new Error('Invalid port number');
            }
        }
    }

    async gatherInformation(ip, port) {
        console.log(colors.info('\n🔍 Starting Information Gathering Phase...'));
        
        const scanResults = {
            nmap: await this.runNmapScan(ip, port),
            dns: await this.runDNSEnumeration(ip),
            services: await this.identifyServices(ip, port),
            vulnerabilities: []
        };

        // Display formatted scan results
        console.log(this.formatScanResults(scanResults));

        // Store results in Neo4j
        await this.storeResults(ip, scanResults);

        // Analyze results
        const analysis = await this.analyzeResults(ip, scanResults);
        
        return analysis;
    }

    async runNmapScan(ip, port) {
        console.log(colors.info('\nRunning Nmap scan...'));
        try {
            const portRange = port ? `-p${port}` : '-p-';
            const { stdout } = await execPromise(`nmap -sV -sC ${portRange} ${ip}`);
            return this.parseNmapOutput(stdout);
        } catch (error) {
            console.log(colors.error('Nmap scan error:', error.message));
            return null;
        }
    }

    parseNmapOutput(output) {
        const services = [];
        const lines = output.split('\n');
        let currentPort = null;

        lines.forEach(line => {
            const portMatch = line.match(/^(\d+)\/(\w+)\s+(\w+)\s+(.+)/);
            if (portMatch) {
                currentPort = {
                    port: portMatch[1],
                    protocol: portMatch[2],
                    state: portMatch[3],
                    service: portMatch[4]
                };
                services.push(currentPort);
            }
        });

        return services;
    }

    async identifyServices(ip, port) {
        console.log(colors.info('\nIdentifying running services...'));
        const services = [];
        
        try {
            // Run service detection
            const { stdout } = await execPromise(`nmap -sV ${ip} ${port ? `-p${port}` : ''}`);
            
            // Parse and store service information
            const serviceLines = stdout.match(/^\d+\/tcp.*$/gm) || [];
            serviceLines.forEach(line => {
                const [port, name, version] = line.split(/\s+/);
                services.push({ port, name, version });
            });
        } catch (error) {
            console.log(colors.error('Service identification error:', error.message));
        }

        return services;
    }

    async runDNSEnumeration(ip) {
        console.log(colors.info('\nPerforming DNS enumeration...'));
        try {
            const { stdout } = await execPromise(`dnsenum ${ip}`);
            return this.parseDNSOutput(stdout);
        } catch (error) {
            console.log(colors.error('DNS enumeration error:', error.message));
            return null;
        }
    }

    async parseDNSOutput(output) {
        const dnsInfo = {
            domains: [],
            nameservers: [],
            mailservers: []
        };

        const lines = output.split('\n');
        lines.forEach(line => {
            if (line.includes('NS:')) {
                const ns = line.split('NS:')[1].trim();
                dnsInfo.nameservers.push(ns);
            }
            if (line.includes('MX:')) {
                const mx = line.split('MX:')[1].trim();
                dnsInfo.mailservers.push(mx);
            }
            if (line.includes('domain:')) {
                const domain = line.split('domain:')[1].trim();
                dnsInfo.domains.push(domain);
            }
        });

        return dnsInfo;
    }

    formatScanResults(scanResults) {
        let output = '';

        // Format NMAP results
        if (scanResults.nmap && scanResults.nmap.length > 0) {
            output += colors.header('\n📡 NMAP Scan Results:\n');
            const nmapHeaders = ['Port', 'Protocol', 'State', 'Service'];
            const nmapRows = scanResults.nmap.map(service => [
                service.port,
                service.protocol,
                service.state,
                service.service
            ]);
            output += this.createTable(nmapHeaders, nmapRows);
        }

        // Format Service Detection results
        if (scanResults.services && scanResults.services.length > 0) {
            output += colors.header('\n🔍 Service Detection Results:\n');
            const serviceHeaders = ['Port', 'Service Name', 'Version'];
            const serviceRows = scanResults.services.map(service => [
                service.port,
                service.name,
                service.version || 'Unknown'
            ]);
            output += this.createTable(serviceHeaders, serviceRows);
        }

        // Format DNS Enumeration results
        if (scanResults.dns) {
            output += colors.header('\n🌐 DNS Enumeration Results:\n');
            
            if (scanResults.dns.nameservers.length > 0) {
                output += colors.subheader('\nNameservers:\n');
                scanResults.dns.nameservers.forEach(ns => {
                    output += colors.bullet + ` ${ns}\n`;
                });
            }

            if (scanResults.dns.mailservers.length > 0) {
                output += colors.subheader('\nMail Servers:\n');
                scanResults.dns.mailservers.forEach(mx => {
                    output += colors.bullet + ` ${mx}\n`;
                });
            }

            if (scanResults.dns.domains.length > 0) {
                output += colors.subheader('\nDomains:\n');
                scanResults.dns.domains.forEach(domain => {
                    output += colors.bullet + ` ${domain}\n`;
                });
            }
        }

        return output;
    }

    async storeResults(ip, results) {
        const session = this.driver.session();
        try {
            await session.run(
                `
                MERGE (host:Host {ip: $ip})
                WITH host
                UNWIND $services as service
                MERGE (s:Service {
                    port: service.port,
                    name: service.name,
                    version: service.version
                })
                MERGE (host)-[:RUNS]->(s)
                `,
                { ip, services: results.services }
            );
        } finally {
            await session.close();
        }
    }

    formatServiceTable(services) {
        const headers = ['Sl.No', 'Port', 'Service Name', 'Service Version'];
        const rows = services.map((service, index) => [
            index + 1,
            service.port,
            service.name || 'Unknown',
            service.version || 'N/A'
        ]);

        return this.createTable(headers, rows);
    }

    formatCVETable(vulnerabilities) {
        const headers = [
            'Sl.No',
            'CVE',
            'Affected Component',
            'Affected Port',
            'Affected Version',
            'Fix Version',
            'Patch URL',
            'Exploit URLs',
            'Metasploit'
        ];

        const rows = vulnerabilities.map((vuln, index) => [
            index + 1,
            vuln.cve || 'N/A',
            vuln.affectedComponent || 'N/A',
            vuln.affectedPort || 'N/A',
            vuln.affectedVersion || 'N/A',
            vuln.fixVersion || 'N/A',
            vuln.patchUrl || 'N/A',
            Array.isArray(vuln.exploitUrls) ? vuln.exploitUrls.join(', ') : 'N/A',
            vuln.hasMetasploit ? 'Yes' : 'No'
        ]);

        return this.createTable(headers, rows);
    }

    async analyzeResults(ip, results) {
        console.log(colors.info('\nAnalyzing results...'));

        // Format results for AI analysis
        const analysisPrompt = `
Analyze these security scan results for ${ip}:
${JSON.stringify(results, null, 2)}

Provide a JSON response with the following structure:
{
    "vulnerabilities": [
        {
            "cve": "CVE ID",
            "affectedComponent": "component name",
            "affectedPort": "port number",
            "affectedVersion": "affected version",
            "fixVersion": "version that fixes it",
            "patchUrl": "URL to patch",
            "exploitUrls": ["URL1", "URL2"],
            "hasMetasploit": true/false
        }
    ],
    "services": [
        {
            "port": "port number",
            "name": "service name",
            "version": "version number"
        }
    ],
    "osInfo": {
        "type": "OS type",
        "version": "OS version"
    },
    "riskAssessment": "detailed risk assessment",
    "attackStrategies": ["strategy1", "strategy2"]
}
`;

        const analysisResponse = await this.analyzer.analyzeOutput(analysisPrompt);
        let analysis;
        try {
            analysis = JSON.parse(analysisResponse);
        } catch (error) {
            console.error(colors.error('Failed to parse analysis response'));
            return null;
        }

        // Format the output
        let output = '';

        // Services Table
        if (analysis.services && analysis.services.length > 0) {
            output += colors.header('\n📊 Detected Services:\n');
            output += this.formatServiceTable(analysis.services);
        }

        // Vulnerabilities Table
        if (analysis.vulnerabilities && analysis.vulnerabilities.length > 0) {
            output += colors.header('\n🔒 Identified Vulnerabilities:\n');
            output += this.formatCVETable(analysis.vulnerabilities);
        }

        // OS Information
        if (analysis.osInfo) {
            output += colors.header('\n💻 Operating System Information:\n');
            output += colors.info(`Type: ${analysis.osInfo.type}\n`);
            output += colors.info(`Version: ${analysis.osInfo.version}\n`);
        }

        // Risk Assessment
        if (analysis.riskAssessment) {
            output += colors.header('\n⚠️ Risk Assessment:\n');
            output += colors.analysis(analysis.riskAssessment + '\n');
        }

        // Attack Strategies
        if (analysis.attackStrategies && analysis.attackStrategies.length > 0) {
            output += colors.header('\n🎯 Potential Attack Strategies:\n');
            analysis.attackStrategies.forEach((strategy, index) => {
                output += colors.bullet + ` ${index + 1}. ${strategy}\n`;
            });
        }

        return output;
    }

    formatVulnerabilityTable(vulnerabilities) {
        const headers = ['Sl.No', 'CVE', 'Component', 'Port', 'Version', 'Fix Version', 'Patch URL', 'Exploits', 'Metasploit'];
        const rows = vulnerabilities.map((vuln, index) => [
            index + 1,
            vuln.cve,
            vuln.component || 'N/A',
            vuln.port || 'N/A',
            vuln.version || 'N/A',
            vuln.fixVersion || 'N/A',
            vuln.patchUrl || 'N/A',
            vuln.exploits?.join(', ') || 'N/A',
            vuln.metasploit ? 'Yes' : 'No'
        ]);

        return this.createTable(headers, rows);
    }

    createTable(headers, rows) {
        // Calculate column widths
        const widths = headers.map((h, i) => 
            Math.max(h.length, ...rows.map(row => String(row[i]).length))
        );

        // Create separator
        const separator = widths.map(w => '-'.repeat(w)).join('-+-');

        // Format header
        const headerRow = headers.map((h, i) => h.padEnd(widths[i])).join(' | ');

        // Format rows
        const formattedRows = rows.map(row =>
            row.map((cell, i) => String(cell).padEnd(widths[i])).join(' | ')
        );

        return [headerRow, separator, ...formattedRows].join('\n');
    }

    async execute(ip, port) {
        try {
            await this.validateInput(ip, port);
            
            console.log(colors.info(`\nStarting HK mode for target: ${ip}${port ? ':' + port : ''}`));
            
            // Initial information gathering
            const analysis = await this.gatherInformation(ip, port);
            console.log(colors.analysis('\nAnalysis Results:'));
            console.log(analysis);

            // Interactive mode
            while (true) {
                const action = await this.promptNextAction();
                if (action === 'end') break;
                
                await this.executeAction(action, ip, port);
            }

        } catch (error) {
            console.error(colors.error('Error:', error.message));
        } finally {
            await this.driver.close();
        }
    }

    async promptNextAction() {
        // Implementation for interactive prompt
        // This would need to be implemented based on your preferred input method
        return 'end'; // Placeholder
    }

    async executeAction(action, ip, port) {
        // Implementation for executing selected actions
        console.log(colors.info(`Executing action: ${action}`));
    }
}

module.exports = HackCommand; 