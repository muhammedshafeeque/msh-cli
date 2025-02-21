const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const puppeteer = require('puppeteer');
const cheerio = require('cheerio');
const { Builder, By, until } = require('selenium-webdriver');
const chrome = require('selenium-webdriver/chrome');
const colors = require('./colors');
const axios = require('axios');
const { execSync } = require('child_process');
const { MistralAnalyzer } = require('./mistralAnalyzer');

class SearchCommands {
    static async launchBrowser() {
        return await puppeteer.launch({
            headless: 'new',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--disable-gpu',
                '--window-size=1920x1080',
                '--ignore-certificate-errors',
                '--ignore-certificate-errors-spki-list'
            ],
            defaultViewport: {
                width: 1920,
                height: 1080
            },
            timeout: 60000
        });
    }

    static async navigateToPage(page, url, options = {}) {
        try {
            await page.setDefaultNavigationTimeout(30000);
            await page.setRequestInterception(true);
            
            // Block unnecessary resources
            page.on('request', (request) => {
                if (['image', 'stylesheet', 'font', 'media'].includes(request.resourceType())) {
                    request.abort();
                } else {
                    request.continue();
                }
            });

            // Add headers to avoid detection
            await page.setExtraHTTPHeaders({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive'
            });

            await page.goto(url, {
                waitUntil: 'networkidle0',
                timeout: 30000,
                ...options
            });
        } catch (error) {
            console.log(colors.warning(`Navigation failed for ${url}: ${error.message}`));
            throw error;
        }
    }

    static async searchExploitDB(query) {
        const browser = await this.launchBrowser();
        try {
            const page = await browser.newPage();
            await this.navigateToPage(page, `https://www.exploit-db.com/search?q=${encodeURIComponent(query)}`);

            // Wait for results to load
            await page.waitForSelector('.vulns-table', { timeout: 30000 });

            const results = await page.evaluate(() => {
                return Array.from(document.querySelectorAll('.vulns-table tbody tr')).map(row => ({
                    title: row.querySelector('td:nth-child(2)')?.textContent?.trim(),
                    type: row.querySelector('td:nth-child(5)')?.textContent?.trim(),
                    date: row.querySelector('td:nth-child(3)')?.textContent?.trim(),
                    link: row.querySelector('td:nth-child(2) a')?.href
                })).filter(r => r.title && r.link);
            });

            return {
                success: true,
                platform: 'ExploitDB',
                results: results.slice(0, 5)
            };
        } catch (error) {
            console.log(colors.warning(`ExploitDB search failed: ${error.message}`));
            return {
                success: false,
                platform: 'ExploitDB',
                results: []
            };
        } finally {
            await browser.close();
        }
    }

    static parseExploitDBResults(stdout) {
        return stdout.split('\n')
            .filter(line => line.trim())
            .map(line => {
                const [title, link] = line.split('|').map(s => s.trim());
                return { title, link };
            });
    }

    static async searchWithPuppeteer(url, query, selectors) {
        const browser = await puppeteer.launch({
            headless: 'new',
            args: ['--no-sandbox']
        });
        
        try {
            const page = await browser.newPage();
            await page.goto(url);
            
            // Wait for selectors and extract data
            const results = await page.evaluate((selectors) => {
                const data = [];
                document.querySelectorAll(selectors.container).forEach(item => {
                    data.push({
                        title: item.querySelector(selectors.title)?.textContent,
                        description: item.querySelector(selectors.description)?.textContent,
                        link: item.querySelector(selectors.link)?.href
                    });
                });
                return data;
            }, selectors);

            return results;
        } finally {
            await browser.close();
        }
    }

    static async searchWithSelenium(url, query) {
        let driver;
        try {
            driver = await new Builder()
                .forBrowser('chrome')
                .setChromeOptions(new chrome.Options().headless())
                .build();

            await driver.get(url);
            await driver.wait(until.elementLocated(By.name('q')), 5000);
            
            // Perform search
            const searchBox = await driver.findElement(By.name('q'));
            await searchBox.sendKeys(query);
            await searchBox.submit();
            
            // Wait for results and extract data
            await driver.wait(until.elementLocated(By.css('.search-result')), 5000);
            const results = await driver.findElements(By.css('.search-result'));
            
            const searchResults = await Promise.all(results.map(async (result) => {
                return {
                    title: await result.findElement(By.css('h3')).getText(),
                    description: await result.findElement(By.css('p')).getText(),
                    link: await result.findElement(By.css('a')).getAttribute('href')
                };
            }));

            return searchResults;
        } finally {
            if (driver) {
                await driver.quit();
            }
        }
    }

    static async searchSecurityBlogs(query) {
        try {
            // Search multiple security blogs
            const blogs = [
                'https://portswigger.net/research',
                'https://www.rapid7.com/blog',
                'https://www.hackerone.com/blog'
            ];

            const results = await Promise.all(blogs.map(async (blog) => {
                try {
                    const response = await axios.get(`${blog}/search?q=${encodeURIComponent(query)}`);
                    return {
                        source: blog,
                        content: response.data
                    };
                } catch (error) {
                    return null;
                }
            }));

            return {
                platform: 'Security Blogs',
                success: true,
                results: results.filter(r => r !== null)
            };
        } catch (error) {
            return {
                platform: 'Security Blogs',
                success: false,
                error: error.message
            };
        }
    }

    static async searchCVE(query) {
        try {
            const response = await axios.get(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}`);
            return {
                platform: 'CVE Database',
                success: true,
                results: response.data
            };
        } catch (error) {
            return {
                platform: 'CVE Database',
                success: false,
                error: error.message
            };
        }
    }

    static async searchGitHub(query) {
        try {
            const response = await axios.get(
                `https://api.github.com/search/repositories?q=${encodeURIComponent(query)}+security`,
                {
                    headers: {
                        'Accept': 'application/vnd.github.v3+json',
                        // Add GitHub token if available
                        ...(process.env.GITHUB_TOKEN && {
                            'Authorization': `token ${process.env.GITHUB_TOKEN}`
                        })
                    }
                }
            );

            return {
                platform: 'GitHub',
                success: true,
                results: response.data.items.map(item => ({
                    name: item.full_name,
                    description: item.description,
                    url: item.html_url,
                    stars: item.stargazers_count
                }))
            };
        } catch (error) {
            return {
                platform: 'GitHub',
                success: false,
                error: error.message
            };
        }
    }

    static async searchGoogle(query) {
        try {
            // Using Custom Search API if key is available
            if (process.env.GOOGLE_API_KEY && process.env.GOOGLE_CX) {
                const response = await axios.get(
                    `https://www.googleapis.com/customsearch/v1`,
                    {
                        params: {
                            key: process.env.GOOGLE_API_KEY,
                            cx: process.env.GOOGLE_CX,
                            q: `${query} security vulnerability exploit`,
                        }
                    }
                );

                return {
                    platform: 'Google',
                    success: true,
                    results: response.data.items.map(item => ({
                        title: item.title,
                        snippet: item.snippet,
                        link: item.link
                    }))
                };
            } else {
                // Fallback to web scraping
                const response = await axios.get(
                    `https://www.google.com/search?q=${encodeURIComponent(query)}+security+vulnerability`
                );
                // Parse response HTML here
                return {
                    platform: 'Google',
                    success: true,
                    results: 'Google search results (API key not configured)'
                };
            }
        } catch (error) {
            return {
                platform: 'Google',
                success: false,
                error: error.message
            };
        }
    }

    static async searchDuckDuckGo(query) {
        console.log(colors.info('Searching DuckDuckGo...'));
        const browser = await this.launchBrowser();
        try {
            const page = await browser.newPage();
            await page.goto(`https://duckduckgo.com/?q=${encodeURIComponent(query)}+security+vulnerability`);
            
            // Wait for results to load
            await page.waitForSelector('.result');
            
            const results = await page.evaluate(() => {
                return Array.from(document.querySelectorAll('.result')).map(result => ({
                    title: result.querySelector('.result__title')?.textContent,
                    description: result.querySelector('.result__snippet')?.textContent,
                    link: result.querySelector('.result__url')?.href
                })).filter(r => r.title && r.description && r.link);
            });

            return {
                success: true,
                platform: 'DuckDuckGo',
                results: results.slice(0, 5)
            };
        } catch (error) {
            console.error(colors.error('DuckDuckGo search error:'), error.message);
            return {
                success: false,
                platform: 'DuckDuckGo',
                results: [],
                error: error.message
            };
        } finally {
            await browser.close();
        }
    }

    static async searchWikipedia(query) {
        console.log(colors.info('Searching Wikipedia...'));
        const browser = await this.launchBrowser();
        try {
            const page = await browser.newPage();
            await page.goto(`https://en.wikipedia.org/w/index.php?search=${encodeURIComponent(query)}`);
            
            const results = await page.evaluate(() => {
                // Check if we're on a direct article page
                const isArticle = document.querySelector('#firstHeading');
                if (isArticle) {
                    return [{
                        title: document.querySelector('#firstHeading')?.textContent,
                        description: document.querySelector('#mw-content-text p')?.textContent,
                        link: window.location.href
                    }];
                }

                // Otherwise get search results
                return Array.from(document.querySelectorAll('.mw-search-result')).map(result => ({
                    title: result.querySelector('.mw-search-result-heading')?.textContent,
                    description: result.querySelector('.searchresult')?.textContent,
                    link: 'https://en.wikipedia.org' + result.querySelector('a')?.getAttribute('href')
                })).filter(r => r.title && r.description && r.link);
            });

            return {
                success: true,
                platform: 'Wikipedia',
                results: results.slice(0, 3)
            };
        } catch (error) {
            console.error(colors.error('Wikipedia search error:'), error.message);
            return {
                success: false,
                platform: 'Wikipedia',
                results: [],
                error: error.message
            };
        } finally {
            await browser.close();
        }
    }

    static formatSearchResults(result) {
        let output = '';
        switch (result.platform) {
            case 'ExploitDB':
                output += colors.header('\n💡 ExploitDB Results:\n');
                output += colors.info('----------------------------------------\n');
                result.results.forEach(exploit => {
                    output += colors.highlight(`\n${exploit.title}\n`);
                    output += colors.path(`URL: ${exploit.link}\n`);
                });
                break;

            case 'GitHub':
                output += colors.header('\n📦 GitHub Repositories:\n');
                output += colors.info('----------------------------------------\n');
                result.results.forEach(repo => {
                    output += colors.highlight(`\n${repo.name} (${repo.stars || '⭐ 0'})\n`);
                    output += colors.commandOutput(`Description: ${repo.description || 'No description'}\n`);
                    output += colors.path(`URL: ${repo.url}\n`);
                });
                break;

            case 'Security Blogs':
                output += colors.header('\n📝 Security Blog Articles:\n');
                output += colors.info('----------------------------------------\n');
                result.results.forEach(article => {
                    output += colors.highlight(`\n${article.title}\n`);
                    output += colors.commandOutput(`${article.description}\n`);
                    output += colors.path(`URL: ${article.link}\n`);
                });
                break;

            case 'CVE Database':
                output += colors.header('\n🔒 CVE Database Results:\n');
                output += colors.info('----------------------------------------\n');
                result.results.forEach(cve => {
                    output += colors.highlight(`\n${cve.id}\n`);
                    output += colors.commandOutput(`${cve.description}\n`);
                });
                break;

            case 'Google':
                output += colors.header('\n🔍 Google Search Results:\n');
                output += colors.info('----------------------------------------\n');
                result.results.forEach(item => {
                    output += colors.highlight(`\n${item.title}\n`);
                    output += colors.commandOutput(`${item.snippet}\n`);
                    output += colors.path(`URL: ${item.link}\n`);
                });
                break;

            case 'DuckDuckGo':
                output += colors.header('\n🦆 DuckDuckGo Results:\n');
                output += colors.info('----------------------------------------\n');
                result.results.forEach(item => {
                    output += colors.highlight(`\n${item.title}\n`);
                    output += colors.commandOutput(`${item.description}\n`);
                    output += colors.path(`URL: ${item.link}\n`);
                });
                break;

            case 'Wikipedia':
                output += colors.header('\n📚 Wikipedia Results:\n');
                output += colors.info('----------------------------------------\n');
                result.results.forEach(item => {
                    output += colors.highlight(`\n${item.title}\n`);
                    output += colors.commandOutput(`${item.description}\n`);
                    output += colors.path(`URL: ${item.link}\n`);
                });
                break;
        }

        return output;
    }

    static async analyzeSearchQuery(query) {
        try {
            const analyzer = new MistralAnalyzer(process.env.MISTRAL_API_KEY);
            const analysisPrompt = `
Analyze this security search query: "${query}"

Provide a JSON object with the following structure:
{
    "category": "type of search (e.g., software vulnerability, exploit, technique, tool)",
    "components": ["list of key components to search for"],
    "relatedTerms": ["related terms and variations"],
    "specificVersions": ["version numbers to look for"],
    "recommendedSources": ["suggested security databases"]
}

Return only the JSON object, no markdown or additional text.
`;
            const analysis = await analyzer.analyzeOutput(analysisPrompt);
            
            // Clean the response to extract only the JSON part
            const jsonStr = analysis.replace(/```json\s*|\s*```/g, '')  // Remove markdown code blocks
                .replace(/[\u200B-\u200D\uFEFF]/g, '')  // Remove zero-width spaces
                .trim();  // Remove extra whitespace
            
            try {
                return JSON.parse(jsonStr);
            } catch (parseError) {
                console.error(colors.error('Failed to parse AI response:'), colors.errorOutput(jsonStr));
                // Return a default analysis structure
                return {
                    category: "security search",
                    components: [query],
                    relatedTerms: [],
                    specificVersions: [],
                    recommendedSources: ["ExploitDB", "CVE", "Security Blogs"]
                };
            }
        } catch (error) {
            console.error(colors.error('Search query analysis failed:'), colors.errorOutput(error.message));
            // Return a default analysis structure
            return {
                category: "security search",
                components: [query],
                relatedTerms: [],
                specificVersions: [],
                recommendedSources: ["ExploitDB", "CVE", "Security Blogs"]
            };
        }
    }

    static async executeSearch(query) {
        console.log(colors.info(`\n🔍 Analyzing search query: ${query}`));
        
        // Analyze the query first
        const queryAnalysis = await this.analyzeSearchQuery(query);
        
        console.log(colors.info('\nSearch Strategy:'));
        console.log(colors.analysis(JSON.stringify(queryAnalysis, null, 2)));

        // Expand search terms using the analysis
        const searchTerms = [
            query,
            ...queryAnalysis.relatedTerms,
            ...queryAnalysis.components.map(c => `${c} vulnerability`)
        ];

        console.log(colors.info('\n🔍 Searching across multiple sources...'));
        
        // Execute searches with expanded terms
        const searchPromises = [
            this.searchExploitDB(query),
            this.searchCVE(query),
            this.searchHackerOne(query),
            this.searchGitHub(query),
            this.searchSecurityBlogs(query),
            this.searchGoogle(searchTerms.join(' ')),
            this.searchWikipedia(query)
        ];

        const results = await Promise.allSettled(searchPromises);
        let allResults = [];
        
        results.forEach(result => {
            if (result.status === 'fulfilled' && result.value) {
                console.log(this.formatResults(result.value));
                allResults.push(result.value);
            }
        });

        // Show comprehensive analysis
        if (allResults.length > 0) {
            console.log(colors.header('\n📊 Comprehensive Analysis'));
            console.log(colors.info('----------------------------------------'));
            console.log(await this.generateAnalysis(query, allResults));
        } else {
            console.log(colors.warning('\nNo results found across any sources.'));
        }
    }

    static async searchHackerOne(query) {
        try {
            const response = await axios.get(`https://hackerone.com/graphql`, {
                params: {
                    query: `
                        query SearchReports($query: String!) {
                            search_queries(query: $query) {
                                nodes {
                                    title
                                    severity
                                    bounty_awarded
                                    resolved_at
                                }
                            }
                        }
                    `,
                    variables: { query }
                }
            });

            return {
                platform: 'HackerOne',
                success: true,
                results: response.data.data.search_queries.nodes
            };
        } catch (error) {
            return {
                platform: 'HackerOne',
                success: false,
                error: error.message
            };
        }
    }

    static formatResults(results) {
        if (!results.success) {
            return colors.error(`\n${results.platform} Search Error: ${results.error}`);
        }

        let output = colors.header(`\n${results.platform} Results:`);
        output += colors.info('\n----------------------------------------');
        
        switch (results.platform) {
            case 'Exploit-DB':
                output += this.formatExploitDBResults(results.results);
                break;
            case 'CVE Database':
                output += this.formatCVEResults(results.results);
                break;
            default:
                output += typeof results.results === 'string' 
                    ? `\n${results.results}`
                    : `\n${JSON.stringify(results.results, null, 2)}`;
        }

        return output;
    }

    static formatExploitDBResults(results) {
        let output = '';
        if (typeof results === 'string') {
            // Format searchsploit CLI output
            const exploits = results.split('\n')
                .filter(line => line.trim())
                .map(line => {
                    const [description, path] = line.split('|').map(s => s.trim());
                    return { description, path };
                });

            // Create a summary table
            output += '\n' + this.createTable(
                ['Description', 'Path'],
                exploits.map(e => [e.description, e.path])
            );

            // Add statistics
            output += '\n\n' + colors.info('Statistics:');
            output += '\n' + colors.bullet + ` Total Exploits Found: ${exploits.length}`;
            
            // Categorize exploits
            const categories = exploits.reduce((acc, exp) => {
                const category = exp.path.split('/')[0];
                acc[category] = (acc[category] || 0) + 1;
                return acc;
            }, {});

            output += '\n\n' + colors.info('Categories:');
            Object.entries(categories).forEach(([category, count]) => {
                output += '\n' + colors.bullet + ` ${category}: ${count} exploits`;
            });
        }
        return output;
    }

    static formatCVEResults(results) {
        let output = '';
        if (results.vulnerabilities) {
            const cves = results.vulnerabilities;

            // Create summary table
            output += '\n' + this.createTable(
                ['CVE ID', 'Severity', 'Published'],
                cves.map(cve => [
                    cve.cve.id,
                    this.getSeverityColor(cve.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore),
                    new Date(cve.cve.published).toLocaleDateString()
                ])
            );

            // Add statistics
            output += '\n\n' + colors.info('Statistics:');
            output += '\n' + colors.bullet + ` Total CVEs Found: ${cves.length}`;

            // Severity distribution
            const severities = cves.reduce((acc, cve) => {
                const severity = this.getSeverityLevel(cve.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore);
                acc[severity] = (acc[severity] || 0) + 1;
                return acc;
            }, {});

            output += '\n\n' + colors.info('Severity Distribution:');
            Object.entries(severities).forEach(([severity, count]) => {
                output += '\n' + colors.bullet + ` ${severity}: ${count} CVEs`;
            });

            // Timeline analysis
            output += '\n\n' + colors.info('Timeline Analysis:');
            const timeline = this.createTimeline(cves);
            output += '\n' + timeline;
        }
        return output;
    }

    static createTable(headers, rows) {
        // Calculate column widths
        const widths = headers.map((h, i) => 
            Math.max(
                h.length,
                ...rows.map(row => (row[i] || '').toString().length)
            )
        );

        // Create separator line
        const separator = widths.map(w => '-'.repeat(w)).join('-+-');

        // Format header
        const headerRow = headers.map((h, i) => h.padEnd(widths[i])).join(' | ');

        // Format rows
        const formattedRows = rows.map(row =>
            row.map((cell, i) => cell.toString().padEnd(widths[i])).join(' | ')
        );

        return colors.table([
            headerRow,
            separator,
            ...formattedRows
        ].join('\n'));
    }

    static getSeverityColor(score) {
        if (!score) return colors.info('N/A');
        if (score >= 9) return colors.critical(`Critical (${score})`);
        if (score >= 7) return colors.high(`High (${score})`);
        if (score >= 4) return colors.medium(`Medium (${score})`);
        return colors.low(`Low (${score})`);
    }

    static getSeverityLevel(score) {
        if (!score) return 'Unknown';
        if (score >= 9) return 'Critical';
        if (score >= 7) return 'High';
        if (score >= 4) return 'Medium';
        return 'Low';
    }

    static createTimeline(cves) {
        const timelineData = cves
            .sort((a, b) => new Date(a.cve.published) - new Date(b.cve.published))
            .map(cve => ({
                date: new Date(cve.cve.published),
                id: cve.cve.id,
                severity: this.getSeverityLevel(cve.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore)
            }));

        let timeline = '';
        let currentYear = null;

        timelineData.forEach(item => {
            const year = item.date.getFullYear();
            if (year !== currentYear) {
                timeline += `\n${colors.year(year)}`;
                currentYear = year;
            }
            timeline += `\n${colors.bullet} ${item.date.toLocaleDateString()} - ${item.id} (${item.severity})`;
        });

        return timeline;
    }

    static async generateAnalysis(query, results) {
        let analysis = '';
        
        // Overall statistics
        const totalFindings = results.reduce((sum, r) => 
            sum + (Array.isArray(r.results) ? r.results.length : 
                  (typeof r.results === 'string' ? r.results.split('\n').length : 1)), 0);

        // Get AI insights
        const analyzer = new MistralAnalyzer(process.env.MISTRAL_API_KEY);
        const aiInsights = await analyzer.analyzeOutput(`
Analyze these security search results for "${query}":
${JSON.stringify(results, null, 2)}

Provide:
1. Key security findings
2. Risk assessment
3. Attack vectors
4. Mitigation strategies
5. Technical details
`);

        analysis += colors.analysis(`
Key Findings for "${query}":
${colors.bullet} Total Results: ${totalFindings}
${colors.bullet} Sources Searched: ${results.length}

Security Implications:
${this.analyzeSecurityImplications(results)}

Risk Assessment:
${this.analyzeRiskLevels(results)}

AI Insights:
${aiInsights}

Recommendations:
${this.generateRecommendations(query, results)}
`);

        return analysis;
    }

    static analyzeSecurityImplications(results) {
        // Analyze and categorize findings
        let implications = '';
        results.forEach(result => {
            if (result.platform === 'CVE Database' && result.results.vulnerabilities) {
                const criticalCVEs = result.results.vulnerabilities
                    .filter(cve => 
                        cve.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore >= 9
                    );
                if (criticalCVEs.length > 0) {
                    implications += `\n${colors.bullet} Found ${criticalCVEs.length} Critical CVEs`;
                }
            }
            if (result.platform === 'Exploit-DB') {
                const exploitCount = typeof result.results === 'string' 
                    ? result.results.split('\n').filter(l => l.trim()).length 
                    : 0;
                if (exploitCount > 0) {
                    implications += `\n${colors.bullet} ${exploitCount} known exploits available`;
                }
            }
        });
        return implications || '\n' + colors.bullet + ' No immediate security implications found';
    }

    static analyzeRiskLevels(results) {
        let riskAnalysis = '';
        const riskLevels = {
            Critical: 0,
            High: 0,
            Medium: 0,
            Low: 0
        };

        results.forEach(result => {
            if (result.platform === 'CVE Database' && result.results.vulnerabilities) {
                result.results.vulnerabilities.forEach(cve => {
                    const severity = this.getSeverityLevel(
                        cve.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore
                    );
                    riskLevels[severity] = (riskLevels[severity] || 0) + 1;
                });
            }
        });

        Object.entries(riskLevels).forEach(([level, count]) => {
            if (count > 0) {
                riskAnalysis += `\n${colors.bullet} ${level}: ${count} findings`;
            }
        });

        return riskAnalysis || '\n' + colors.bullet + ' No risk levels identified';
    }

    static generateRecommendations(query, results) {
        let recommendations = '';
        
        // Basic recommendations based on findings
        if (results.some(r => r.platform === 'CVE Database' && r.results.vulnerabilities?.length > 0)) {
            recommendations += `\n${colors.bullet} Regular security updates recommended`;
            recommendations += `\n${colors.bullet} Implement vulnerability management system`;
        }
        
        if (results.some(r => r.platform === 'Exploit-DB' && r.results)) {
            recommendations += `\n${colors.bullet} Review and patch known vulnerabilities`;
            recommendations += `\n${colors.bullet} Implement security monitoring`;
        }

        // Add general recommendations
        recommendations += `\n${colors.bullet} Conduct regular security assessments`;
        recommendations += `\n${colors.bullet} Monitor security advisories`;

        return recommendations;
    }
}

module.exports = SearchCommands; 