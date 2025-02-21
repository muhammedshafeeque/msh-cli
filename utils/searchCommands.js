const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const puppeteer = require('puppeteer');
const cheerio = require('cheerio');
const { Builder, By, until } = require('selenium-webdriver');
const chrome = require('selenium-webdriver/chrome');
const colors = require('./colors');

class SearchCommands {
    static async searchExploitDB(query) {
        try {
            const result = await execPromise(`searchsploit ${query} -w -t`);
            return {
                success: true,
                platform: 'ExploitDB',
                results: result.stdout,
                error: result.stderr
            };
        } catch (error) {
            return {
                success: false,
                platform: 'ExploitDB',
                results: '',
                error: error.message
            };
        }
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
            'https://portswigger.net/research/articles',
            'https://www.hackerone.com/vulnerability-reports',
            'https://www.exploit-db.com/papers'
        ];

        const results = [];
        for (const blog of blogs) {
            try {
                const browser = await puppeteer.launch({ headless: 'new' });
                const page = await browser.newPage();
                await page.goto(blog);
                
                // Search and extract relevant content
                const blogResults = await page.evaluate((query) => {
                    const articles = document.querySelectorAll('article');
                    return Array.from(articles)
                        .filter(article => article.textContent.toLowerCase().includes(query.toLowerCase()))
                        .map(article => ({
                            title: article.querySelector('h2')?.textContent,
                            description: article.querySelector('p')?.textContent,
                            link: article.querySelector('a')?.href
                        }));
                }, query);

                results.push(...blogResults);
                await browser.close();
            } catch (error) {
                console.error(`Error scraping ${blog}:`, error);
            }
        }

        return {
            success: true,
            platform: 'Security Blogs',
            results: results
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

    static formatSearchResults(results) {
        let output = '';
        
        switch (results.platform) {
            case 'ExploitDB':
                output += colors.header('\n📊 ExploitDB Results:\n');
                output += colors.info('----------------------------------------\n');
                output += colors.commandOutput(results.results);
                break;

            case 'GitHub':
                output += colors.header('\n📦 GitHub Repositories:\n');
                output += colors.info('----------------------------------------\n');
                results.results.forEach(repo => {
                    output += colors.highlight(`\n${repo.name} (${repo.stars || '⭐ 0'})\n`);
                    output += colors.commandOutput(`Description: ${repo.description || 'No description'}\n`);
                    output += colors.path(`URL: ${repo.url}\n`);
                });
                break;

            case 'Security Blogs':
                output += colors.header('\n📝 Security Blog Articles:\n');
                output += colors.info('----------------------------------------\n');
                results.results.forEach(article => {
                    output += colors.highlight(`\n${article.title}\n`);
                    output += colors.commandOutput(`${article.description}\n`);
                    output += colors.path(`URL: ${article.link}\n`);
                });
                break;

            case 'CVE Database':
                output += colors.header('\n🔒 CVE Database Results:\n');
                output += colors.info('----------------------------------------\n');
                results.results.forEach(cve => {
                    output += colors.highlight(`\n${cve.id}\n`);
                    output += colors.commandOutput(`${cve.description}\n`);
                });
                break;
        }

        return output;
    }

    static async analyzeSearchResults(results, query) {
        return {
            query,
            platforms: results.map(r => r.platform),
            totalResults: results.reduce((acc, r) => acc + r.results.length, 0),
            summary: results.map(r => ({
                platform: r.platform,
                count: r.results.length,
                highlights: r.results.slice(0, 3)
            }))
        };
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
}

module.exports = SearchCommands; 