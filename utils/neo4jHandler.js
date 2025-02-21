class Neo4jHandler {
    static async storeInNeo4j(driver, data) {
        const session = driver.session();
        try {
            if (data.type === 'chat') {
                // Special handling for chat messages
                await session.run(
                    `
                    CREATE (c:Chat {
                        type: $type,
                        query: $query,
                        response: $response,
                        timestamp: $timestamp
                    })
                    `,
                    {
                        type: data.type,
                        query: data.query,
                        response: data.response,
                        timestamp: data.timestamp
                    }
                );
            } else {
                // Regular analysis storage
                await session.run(
                    `
                    CREATE (a:Analysis {
                        content: $content,
                        analysis: $analysis,
                        timestamp: $timestamp
                    })
                    `,
                    {
                        content: data.content,
                        analysis: data.analysis,
                        timestamp: data.timestamp
                    }
                );
            }
        } finally {
            await session.close();
        }
    }

    static async getGraphContext(driver) {
        const session = driver.session();
        try {
            const result = await session.run(
                `
                MATCH (a:Analysis)
                RETURN a
                ORDER BY a.timestamp DESC
                LIMIT 10
                `
            );
            return result.records.map(record => record.get('a').properties);
        } finally {
            await session.close();
        }
    }
}

module.exports = {
    storeInNeo4j: Neo4jHandler.storeInNeo4j,
    getGraphContext: Neo4jHandler.getGraphContext
}; 