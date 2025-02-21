const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const puppeteer = require('puppeteer');
const cheerio = require('cheerio');
const { Builder, By, until } = require('selenium-webdriver');
const chrome = require('selenium-webdriver/chrome');
const colors = require('./colors');

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
        const blogs = [
            {
                url: 'https://www.rapid7.com/blog/search/',
                selectors: {
                    results: '.blog-post',
                    title: '.blog-post-title',
                    description: '.blog-post-excerpt',
                    link: '.blog-post-title a'
                }
            },
            {
                url: 'https://www.securityfocus.com/search',
                selectors: {
                    results: '.result-item',
                    title: '.title',
                    description: '.description',
                    link: '.title a'
                }
            }
        ];

        const results = [];
        for (const blog of blogs) {
            const browser = await this.launchBrowser();
            try {
                const page = await browser.newPage();
                await this.navigateToPage(page, `${blog.url}${encodeURIComponent(query)}`);

                const blogResults = await page.evaluate((selectors) => {
                    return Array.from(document.querySelectorAll(selectors.results)).map(item => ({
                        title: item.querySelector(selectors.title)?.textContent?.trim(),
                        description: item.querySelector(selectors.description)?.textContent?.trim(),
                        link: item.querySelector(selectors.link)?.href
                    })).filter(r => r.title && r.link);
                }, blog.selectors);

                results.push(...blogResults);
            } catch (error) {
                console.log(colors.warning(`Failed to scrape ${blog.url}: ${error.message}`));
            } finally {
                await browser.close();
            }
        }

        return {
            success: true,
            platform: 'Security Blogs',
            results: results.slice(0, 5)
        };
    }

    static async searchCVE(query) {
        const browser = await puppeteer.launch({ headless: 'new' });
        try {
            const page = await browser.newPage();
            await page.goto(`https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=${query}`);
            
            const cveResults = await page.evaluate(() => {
                const cves = document.querySelectorAll('tr');
                return Array.from(cves).map(cve => ({
                    id: cve.querySelector('td:first-child')?.textContent,
                    description: cve.querySelector('td:last-child')?.textContent
                })).filter(result => result.id && result.description);
            });

            return {
                success: true,
                platform: 'CVE Database',
                results: cveResults
            };
        } finally {
            await browser.close();
        }
    }

    static async searchGitHub(query) {
        const browser = await puppeteer.launch({ headless: 'new' });
        try {
            const page = await browser.newPage();
            await page.goto(`https://github.com/search?q=${encodeURIComponent(query)}&type=repositories`);
            
            const repos = await page.evaluate(() => {
                return Array.from(document.querySelectorAll('.repo-list-item')).map(repo => ({
                    name: repo.querySelector('a')?.textContent,
                    description: repo.querySelector('p')?.textContent,
                    url: 'https://github.com' + repo.querySelector('a')?.getAttribute('href'),
                    stars: repo.querySelector('.muted-link')?.textContent
                }));
            });

            return {
                success: true,
                platform: 'GitHub',
                results: repos
            };
        } finally {
            await browser.close();
        }
    }

    static async searchGoogle(query) {
        console.log(colors.info('Searching Google...'));
        const browser = await this.launchBrowser();
        try {
            const page = await browser.newPage();
            await page.goto(`https://www.google.com/search?q=${encodeURIComponent(query)}+security+vulnerability`);
            
            const results = await page.evaluate(() => {
                return Array.from(document.querySelectorAll('.g')).map(result => ({
                    title: result.querySelector('h3')?.textContent,
                    description: result.querySelector('.VwiC3b')?.textContent,
                    link: result.querySelector('a')?.href
                })).filter(r => r.title && r.description && r.link);
            });

            return {
                success: true,
                platform: 'Google',
                results: results.slice(0, 5)
            };
        } catch (error) {
            console.error(colors.error('Google search error:'), error.message);
            return {
                success: false,
                platform: 'Google',
                results: [],
                error: error.message
            };
        } finally {
            await browser.close();
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
                    output += colors.commandOutput(`${item.description}\n`);
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

    static async analyzeSearchResults(results, query) {
        return `
Search Analysis for: "${query}"

Total Results Found:
${results.map(r => `- ${r.platform}: ${r.results.length} results`).join('\n')}

Key Findings by Platform:

${results.map(r => `
${r.platform}:
${r.results.slice(0, 3).map(item => `- ${item.title || item.id || 'Untitled'}`).join('\n')}`).join('\n')}

Please provide a comprehensive security analysis including:
1. Security Implications
   - Potential threats identified
   - Known vulnerabilities
   - Attack vectors

2. Risk Assessment
   - Severity levels
   - Exploitation potential
   - Impact analysis

3. Technical Details
   - Affected systems/versions
   - Attack mechanisms
   - Technical vulnerabilities

4. Mitigation Strategies
   - Security patches
   - Preventive measures
   - Best practices

5. Additional Resources
   - Related CVEs
   - Security tools
   - Further reading

6. Timeline & History
   - Discovery dates
   - Patch availability
   - Notable incidents
`;
    }

    static getPentestCommands() {
        return {
            'category': {
                description: 'Category Description',
                subcommands: {
                    'tool-name': 'tool-command',
                }
            }
        };
    }

    static async checkSetup() {
        try {
            // Test browser launch
            const browser = await this.launchBrowser();
            await browser.close();
            
            // Test searchsploit
            await execPromise('which searchsploit');
            
            return true;
        } catch (error) {
            console.log(colors.warning('\nSome search features may be limited. To enable all features:'));
            console.log(colors.info('\n1. Install searchsploit:'));
            console.log(colors.commandOutput('   sudo apt-get update && sudo apt-get install -y exploitdb'));
            console.log(colors.info('\n2. Install Chrome dependencies:'));
            console.log(colors.commandOutput('   sudo apt-get install -y chromium-browser'));
            return false;
        }
    }

    static async visitWebsite(url, depth = 1) {
        console.log(colors.info(`\n🌐 Visiting website: ${url}`));
        const browser = await this.launchBrowser();
        const visitedUrls = new Set();
        const knowledge = [];

        try {
            const page = await browser.newPage();
            await this.navigateToPage(page, url);

            // Extract main content
            const mainContent = await this.extractPageContent(page);
            knowledge.push({
                url: url,
                title: mainContent.title,
                content: mainContent.content,
                links: mainContent.links
            });

            // Recursively visit related links if depth > 0
            if (depth > 0 && mainContent.links.length > 0) {
                const relatedLinks = mainContent.links
                    .filter(link => link.startsWith(new URL(url).origin))
                    .slice(0, 5); // Limit to 5 related links

                for (const link of relatedLinks) {
                    if (!visitedUrls.has(link)) {
                        visitedUrls.add(link);
                        console.log(colors.info(`\nExploring related link: ${link}`));
                        const subPage = await browser.newPage();
                        try {
                            await this.navigateToPage(subPage, link);
                            const subContent = await this.extractPageContent(subPage);
                            knowledge.push({
                                url: link,
                                title: subContent.title,
                                content: subContent.content,
                                links: subContent.links
                            });
                        } catch (error) {
                            console.log(colors.warning(`Failed to explore ${link}: ${error.message}`));
                        } finally {
                            await subPage.close();
                        }
                    }
                }
            }

            return {
                success: true,
                platform: 'Website Analysis',
                results: knowledge
            };

        } catch (error) {
            console.error(colors.error('Website analysis error:'), error.message);
            return {
                success: false,
                platform: 'Website Analysis',
                results: [],
                error: error.message
            };
        } finally {
            await browser.close();
        }
    }

    static async extractPageContent(page) {
        return await page.evaluate(() => {
            // Helper function to clean text
            const cleanText = (text) => {
                return text.replace(/\s+/g, ' ').trim();
            };

            // Get page title
            const title = document.title;

            // Get main content
            const contentSelectors = [
                'article',
                'main',
                '.content',
                '#content',
                '.post-content',
                '.article-content'
            ];

            let content = '';
            for (const selector of contentSelectors) {
                const element = document.querySelector(selector);
                if (element) {
                    content = cleanText(element.textContent);
                    break;
                }
            }

            // If no main content found, get body text
            if (!content) {
                content = cleanText(document.body.textContent);
            }

            // Extract relevant links
            const links = Array.from(document.querySelectorAll('a[href]'))
                .map(a => a.href)
                .filter(href => 
                    href.startsWith('http') && 
                    !href.includes('facebook.com') &&
                    !href.includes('twitter.com') &&
                    !href.includes('linkedin.com')
                );

            // Extract technical information
            const technicalInfo = {
                headers: Array.from(document.querySelectorAll('h1, h2, h3'))
                    .map(h => cleanText(h.textContent)),
                codeBlocks: Array.from(document.querySelectorAll('pre, code'))
                    .map(c => cleanText(c.textContent)),
                lists: Array.from(document.querySelectorAll('ul, ol'))
                    .map(l => cleanText(l.textContent))
            };

            return {
                title,
                content: content.substring(0, 10000), // Limit content length
                links,
                technicalInfo
            };
        });
    }

    static formatWebsiteResults(result) {
        let output = '';
        output += colors.header('\n🌐 Website Analysis Results:\n');
        output += colors.info('----------------------------------------\n');

        result.results.forEach(page => {
            output += colors.highlight(`\n${page.title}\n`);
            output += colors.path(`URL: ${page.url}\n`);
            output += colors.commandOutput(`Content Summary: ${page.content.substring(0, 200)}...\n`);
            
            if (page.technicalInfo?.headers?.length > 0) {
                output += colors.info('\nKey Topics:\n');
                page.technicalInfo.headers.forEach(header => {
                    output += colors.bullet + ' ' + colors.commandOutput(header) + '\n';
                });
            }

            if (page.technicalInfo?.codeBlocks?.length > 0) {
                output += colors.info('\nTechnical Details Found\n');
            }

            if (page.links.length > 0) {
                output += colors.info('\nRelated Links:\n');
                page.links.slice(0, 3).forEach(link => {
                    output += colors.path(`${link}\n`);
                });
            }

            output += colors.info('----------------------------------------\n');
        });

        return output;
    }

    static async analyzeWebsiteContent(results, query) {
        return `
Website Analysis for: "${query}"

Content Overview:
${results.map(page => `
Page: ${page.title}
URL: ${page.url}
Key Topics:
${page.technicalInfo?.headers?.slice(0, 5).map(h => `- ${h}`).join('\n') || 'No headers found'}

Technical Information:
${page.technicalInfo?.codeBlocks?.length ? '- Contains code examples/technical details' : '- No code examples found'}
${page.technicalInfo?.lists?.length ? '- Contains structured information lists' : '- No structured lists found'}
`).join('\n')}

Please analyze this content for:
1. Technical Insights
   - Key technologies mentioned
   - Technical specifications
   - Implementation details

2. Security Implications
   - Potential vulnerabilities
   - Security considerations
   - Risk factors

3. Knowledge Extraction
   - Core concepts
   - Best practices
   - Important findings

4. Recommendations
   - Further research areas
   - Related technologies
   - Implementation guidance

5. Additional Context
   - Related resources
   - Expert opinions
   - Community feedback
`;
    }
}

module.exports = SearchCommands; 