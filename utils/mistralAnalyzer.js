const { Mistral } = require("@mistralai/mistralai");
const colors = require('./colors');

class MistralAnalyzer {
    static async analyzeWithMistral(apiKey, content, graphContext = null) {
        const mistral = new Mistral({
            apiKey: apiKey
        });

        // Show analysis progress
        console.log(colors.bullet, colors.analysisProgress('Initializing analysis...'));
        
        const prompt = graphContext 
            ? `Analyze this terminal output in the context of the following graph data: ${JSON.stringify(graphContext)}\n\nTerminal output:\n${content}`
            : `Analyze this terminal output for security implications and patterns:\n${content}`;

        try {
            console.log(colors.bullet, colors.analysisProgress('Sending request to Mistral AI...'));
            
            const response = await mistral.chat.complete({
                model: "mistral-small-latest",
                stream: false,
                messages: [{
                    role: "user",
                    content: prompt
                }],
                response_format: { type: 'json_object' }
            });

            console.log(colors.bullet, colors.analysisProgress('Processing response...'));

            const analysisResult = {
                analysis: response.choices[0].message.content,
                timestamp: new Date().toISOString(),
                content: content
            };

            // Display formatted analysis
            console.log('\n' + colors.header('📊 Analysis Results'));
            console.log(colors.info('----------------------------------------'));
            
            try {
                const parsedAnalysis = JSON.parse(analysisResult.analysis);
                
                // Display each section of the analysis
                if (parsedAnalysis.summary) {
                    console.log(colors.analysisSection('Summary', parsedAnalysis.summary));
                }
                
                if (parsedAnalysis.security_implications) {
                    console.log(colors.analysisSection('Security Implications', 
                        Array.isArray(parsedAnalysis.security_implications) 
                            ? parsedAnalysis.security_implications.join('\n  • ')
                            : parsedAnalysis.security_implications
                    ));
                }
                
                if (parsedAnalysis.recommendations) {
                    console.log(colors.analysisSection('Recommendations',
                        Array.isArray(parsedAnalysis.recommendations)
                            ? parsedAnalysis.recommendations.join('\n  • ')
                            : parsedAnalysis.recommendations
                    ));
                }
                
                console.log(colors.info('----------------------------------------'));
            } catch {
                // Fallback for non-JSON responses
                console.log(colors.analysisResult(analysisResult.analysis));
            }

            return analysisResult;
        } catch (error) {
            console.error(colors.error('Error querying Mistral API:'), colors.errorOutput(error));
            throw error;
        }
    }

    static async chatWithMistral(apiKey, userMessage) {
        const mistral = new Mistral({
            apiKey: apiKey
        });

        console.log(colors.bullet, colors.analysisProgress('Sending message to Mistral AI...'));
        
        try {
            const response = await mistral.chat.complete({
                model: "mistral-small-latest",
                stream: false,
                messages: [{
                    role: "user",
                    content: userMessage
                }]
            });

            return {
                response: response.choices[0].message.content,
                timestamp: new Date().toISOString(),
                query: userMessage
            };
        } catch (error) {
            console.error(colors.error('Error chatting with Mistral AI:'), colors.errorOutput(error));
            throw error;
        }
    }
}

module.exports = {
    analyzeWithMistral: MistralAnalyzer.analyzeWithMistral,
    chatWithMistral: MistralAnalyzer.chatWithMistral
}; 