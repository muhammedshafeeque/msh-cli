const fs = require('fs').promises;
const path = require('path');
const colors = require('./colors');
const { analyzeWithMistral } = require('./mistralAnalyzer');

class CodeAnalyzer {
    static async analyzeCodebase(apiKey) {
        console.log(colors.info('\n🔍 Analyzing codebase for improvements...'));
        
        try {
            // Get all JavaScript files
            const files = await this.getJavaScriptFiles('./');
            const codeAnalysis = {};

            for (const file of files) {
                const content = await fs.readFile(file, 'utf8');
                console.log(colors.info(`\nAnalyzing ${file}...`));

                const analysis = await this.analyzeFile(file, content, apiKey);
                codeAnalysis[file] = analysis;
            }

            return codeAnalysis;
        } catch (error) {
            console.error(colors.error('Error analyzing codebase:'), error);
            return null;
        }
    }

    static async getJavaScriptFiles(dir) {
        const files = [];
        const items = await fs.readdir(dir, { withFileTypes: true });

        for (const item of items) {
            const fullPath = path.join(dir, item.name);
            if (item.isDirectory() && !item.name.startsWith('.') && item.name !== 'node_modules') {
                files.push(...await this.getJavaScriptFiles(fullPath));
            } else if (item.isFile() && item.name.endsWith('.js')) {
                files.push(fullPath);
            }
        }

        return files;
    }

    static async analyzeFile(filePath, content, apiKey) {
        const analysisPrompt = `
Analyze this JavaScript file for potential improvements:
File: ${filePath}

Code:
${content}

Please provide:
1. Code Quality Assessment
   - Potential bugs
   - Performance issues
   - Security vulnerabilities
   - Code smells

2. Improvement Suggestions
   - Refactoring opportunities
   - Better patterns/practices
   - Error handling improvements
   - Performance optimizations

3. Security Analysis
   - Security risks
   - Input validation issues
   - Authentication/authorization concerns
   - Data handling risks

4. Specific Code Changes
   - Provide exact code modifications
   - Include line numbers
   - Show before/after examples

Format the response as structured JSON with sections.
`;

        const analysis = await analyzeWithMistral(apiKey, analysisPrompt);
        return JSON.parse(analysis.analysis);
    }

    static async applyCodeFix(filePath, fixes, apiKey) {
        try {
            console.log(colors.info(`\nApplying fixes to ${filePath}...`));
            
            // Read current file content
            const content = await fs.readFile(filePath, 'utf8');
            
            // Validate fixes with AI
            const validationPrompt = `
Validate these code changes before applying:
File: ${filePath}

Current Code:
${content}

Proposed Changes:
${JSON.stringify(fixes, null, 2)}

Please verify:
1. Changes are safe to apply
2. No syntax errors introduced
3. Logic remains intact
4. No security vulnerabilities added

Return JSON with validation result and safe code changes.
`;

            const validation = await analyzeWithMistral(apiKey, validationPrompt);
            const validatedFixes = JSON.parse(validation.analysis);

            if (validatedFixes.safe) {
                // Apply validated fixes
                let updatedContent = content;
                for (const fix of validatedFixes.changes) {
                    updatedContent = this.applyFix(updatedContent, fix);
                }

                // Create backup
                await fs.writeFile(`${filePath}.backup`, content);

                // Write updated content
                await fs.writeFile(filePath, updatedContent);

                console.log(colors.success(`✓ Successfully updated ${filePath}`));
                console.log(colors.info('Backup created at:'), colors.path(`${filePath}.backup`));

                return true;
            } else {
                console.log(colors.warning(`Fixes for ${filePath} were deemed unsafe:`));
                console.log(colors.errorOutput(validatedFixes.reason));
                return false;
            }
        } catch (error) {
            console.error(colors.error(`Error applying fixes to ${filePath}:`), error);
            return false;
        }
    }

    static applyFix(content, fix) {
        const lines = content.split('\n');
        
        switch (fix.type) {
            case 'replace':
                lines[fix.line - 1] = fix.newCode;
                break;
            case 'insert':
                lines.splice(fix.line - 1, 0, fix.code);
                break;
            case 'delete':
                lines.splice(fix.line - 1, fix.count || 1);
                break;
            case 'update':
                const start = fix.range.start - 1;
                const end = fix.range.end - 1;
                lines.splice(start, end - start + 1, ...fix.newCode.split('\n'));
                break;
        }

        return lines.join('\n');
    }

    static async debugFunction(functionName, testCases, apiKey) {
        console.log(colors.info(`\n🔍 Debugging function: ${functionName}`));

        const debugPrompt = `
Analyze this function and test cases for debugging:
Function: ${functionName}

Test Cases:
${JSON.stringify(testCases, null, 2)}

Please provide:
1. Test Results Analysis
2. Identified Issues
3. Fix Suggestions
4. Additional Test Cases

Return as JSON with sections.
`;

        try {
            const analysis = await analyzeWithMistral(apiKey, debugPrompt);
            const debugResults = JSON.parse(analysis.analysis);

            console.log(colors.header('\nDebug Analysis:'));
            console.log(colors.info('----------------------------------------'));
            
            if (debugResults.issues.length > 0) {
                console.log(colors.warning('\nIdentified Issues:'));
                debugResults.issues.forEach(issue => {
                    console.log(colors.bullet, colors.errorOutput(issue));
                });

                console.log(colors.info('\nSuggested Fixes:'));
                debugResults.fixes.forEach(fix => {
                    console.log(colors.bullet, colors.commandOutput(fix));
                });
            } else {
                console.log(colors.success('\n✓ No issues found'));
            }

            return debugResults;
        } catch (error) {
            console.error(colors.error('Debug analysis error:'), error);
            return null;
        }
    }
}

module.exports = CodeAnalyzer; 