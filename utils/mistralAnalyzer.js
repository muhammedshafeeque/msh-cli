const { Mistral } = require("@mistralai/mistralai");
const colors = require('./colors');

class MistralAnalyzer {
    constructor(apiKey) {
        this.client = new Mistral({
            apiKey: apiKey
        });
        this.requestQueue = [];
        this.isProcessing = false;
        this.retryDelay = 2000; // Start with 2 seconds
        this.maxRetries = 5;
        this.maxRetryDelay = 32000; // Max 32 seconds
    }

    async analyzeOutput(output, type = 'detailed') {
        let retries = 0;
        let delay = this.retryDelay;

        while (retries < this.maxRetries) {
            try {
                const context = type === 'summary' ? 
                    this.getSummaryPrompt(output) : 
                    this.getDetailedPrompt(output);
                
                if (retries > 0) {
                    console.log(colors.info(`Attempt ${retries + 1} of ${this.maxRetries}...`));
                }

                const response = await this.client.chat.complete({
                    model: "mistral-small-latest",
                    messages: [{ role: "user", content: context }],
                    stream: false,
                    max_tokens: 2048
                });

                return response.choices[0].message.content;

            } catch (error) {
                if (error.message.includes('rate limit') && retries < this.maxRetries - 1) {
                    console.log(colors.warning(`\nRate limit reached, waiting ${delay/1000} seconds...`));
                    await new Promise(resolve => setTimeout(resolve, delay));
                    delay = Math.min(delay * 2, this.maxRetryDelay);
                    retries++;
                    continue;
                }
                throw error;
            }
        }

        throw new Error('Maximum retry attempts reached');
    }

    getDetailedPrompt(output) {
        return `Analyze this command output from a security perspective:

${output}

Provide:
1. Security implications
2. Potential vulnerabilities or risks
3. Recommended security measures
4. Related security tools to investigate
5. Notable patterns or indicators
`;
    }

    getSummaryPrompt(output) {
        return `Provide a brief security-focused summary of this command output:

${output}

Focus on key security findings and immediate actions needed.`;
    }

    async analyzeWithContext(output, context) {
        // Add context-aware analysis here
        const prompt = `Analyze this output with the following context: ${context}\n\nOutput: ${output}`;
        return this.analyzeOutput(prompt);
    }

    static async analyzeWithMistral(apiKey, content, graphContext = null) {
        // Validate parameters
        if (!apiKey) throw new Error('API key is required');
        if (!content || typeof content !== 'string') {
            console.error(colors.error('\n❌ Invalid content for analysis'));
            return {
                analysis: "No valid content to analyze",
                error: true,
                timestamp: new Date().toISOString()
            };
        }

        const mistral = new Mistral({ apiKey });
        console.log(colors.bullet, colors.analysisProgress('Initializing analysis...'));

        try {
            // Clean and prepare the content
            const cleanContent = content.trim();
            if (!cleanContent) {
                return {
                    analysis: "Empty content provided",
                    error: true,
                    timestamp: new Date().toISOString()
                };
            }

            // Prepare the analysis prompt with proper structure
            const analysisPrompt = `
As a cybersecurity expert, analyze the following command output:

${graphContext ? `Context: ${JSON.stringify(graphContext)}\n` : ''}
Content: ${cleanContent}

Provide a structured analysis including:
1. Security Assessment:
   - Immediate security implications
   - Potential vulnerabilities
   - Risk level assessment

2. Technical Analysis:
   - Key findings
   - Notable patterns
   - Suspicious indicators

3. Recommendations:
   - Security measures
   - Mitigation steps
   - Best practices

4. Further Investigation:
   - Additional tools to use
   - Areas to explore
   - Related security checks

Please format the response in a clear, structured manner.
`;

            console.log(colors.bullet, colors.analysisProgress('Sending request to Mistral AI...'));
            
            const response = await mistral.chat.complete({
                model: "mistral-small-latest",
                messages: [
                    {
                        role: "system",
                        content: "You are an expert cybersecurity analyst providing detailed security assessments."
                    },
                    {
                        role: "user",
                        content: analysisPrompt
                    }
                ],
                temperature: 0.3,
                max_tokens: 2048
            });

            if (!response?.choices?.[0]?.message?.content) {
                throw new Error('Invalid response from Mistral AI');
            }

            return {
                analysis: response.choices[0].message.content,
                timestamp: new Date().toISOString(),
                error: false
            };

        } catch (error) {
            console.error(colors.error('\n❌ Mistral AI Error:'), colors.errorOutput(error.message));
            return {
                analysis: `Analysis failed: ${error.message}`,
                error: true,
                timestamp: new Date().toISOString()
            };
        }
    }

    static formatSection(section) {
        if (Array.isArray(section)) {
            return section.map(item => `• ${item}`).join('\n');
        } else if (typeof section === 'object') {
            return Object.entries(section)
                .map(([key, value]) => `${key}:\n${Array.isArray(value) ? 
                    value.map(item => `  • ${item}`).join('\n') : 
                    `  • ${value}`}`)
                .join('\n\n');
        }
        return section;
    }

    static async chatWithMistral(apiKey, userMessage, history = []) {
        if (!apiKey) throw new Error('API key is required');
        if (!userMessage || typeof userMessage !== 'string') {
            return {
                response: "Invalid message provided",
                error: true,
                timestamp: new Date().toISOString()
            };
        }

        try {
            const mistral = new Mistral({ apiKey });
            console.log(colors.bullet, colors.analysisProgress('Processing chat message...'));

            const messages = [
                {
                    role: "system",
                    content: "You are a cybersecurity expert assistant providing detailed security guidance and analysis."
                },
                ...history,
                {
                    role: "user",
                    content: userMessage.trim()
                }
            ];

            const response = await mistral.chat.complete({
                model: "mistral-small-latest",
                messages: messages,
                temperature: 0.7,
                max_tokens: 2048
            });

            if (!response?.choices?.[0]?.message?.content) {
                throw new Error('Invalid response from Mistral AI');
            }

            return {
                response: response.choices[0].message.content,
                timestamp: new Date().toISOString(),
                error: false
            };

        } catch (error) {
            console.error(colors.error('\n❌ Chat Error:'), colors.errorOutput(error.message));
            return {
                response: "An error occurred during the chat. Please try again.",
                error: true,
                timestamp: new Date().toISOString()
            };
        }
    }

    // Add queue processing method
    async processQueue() {
        if (this.isProcessing || this.requestQueue.length === 0) {
            return;
        }

        this.isProcessing = true;

        try {
            const request = this.requestQueue.shift();
            await request();
        } finally {
            this.isProcessing = false;
            if (this.requestQueue.length > 0) {
                // Wait before processing next request
                setTimeout(() => this.processQueue(), 1000);
            }
        }
    }

    // Add request to queue
    async queueRequest(request) {
        return new Promise((resolve, reject) => {
            this.requestQueue.push(async () => {
                try {
                    const result = await request();
                    resolve(result);
                } catch (error) {
                    reject(error);
                }
            });

            if (!this.isProcessing) {
                this.processQueue();
            }
        });
    }
}

module.exports = {
    MistralAnalyzer,
    analyzeOutput: (output, type) => {
        const analyzer = new MistralAnalyzer(process.env.MISTRAL_API_KEY);
        return analyzer.analyzeOutput(output, type);
    },
    analyzeWithMistral: MistralAnalyzer.analyzeWithMistral,
    chatWithMistral: MistralAnalyzer.chatWithMistral
}; 