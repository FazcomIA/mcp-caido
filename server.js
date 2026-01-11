import http from 'http';
import url from 'url';
import 'dotenv/config'; // Load .env file
import client from './api-client.js';

// =========================================
// Configuration
// =========================================

const PORT = process.env.MCP_PORT || 3000;
const API_KEY = process.env.MCP_API_KEY || "mcp-dev-key";

// =========================================
// Tool Definitions
// =========================================

const TOOLS = {
    sendRequest: {
        name: "sendRequest",
        description: "Send HTTP request via Caido",
        parameters: {
            type: "object",
            properties: {
                url: { type: "string" },
                method: { type: "string", default: "GET" },
                headers: { type: "object" },
                body: { type: "string" }
            },
            required: ["url"]
        }
    },
    getFindings: {
        name: "getFindings",
        description: "Get findings from Caido",
        parameters: {
            type: "object",
            properties: {
                limit: { type: "number", default: 20 }
            }
        }
    },
    getRequestHistory: {
        name: "getRequestHistory",
        description: "Get request history from Caido",
        parameters: {
            type: "object",
            properties: {
                limit: { type: "number", default: 20 }
            }
        }
    },
    scanForVulnerabilities: {
        name: "scanForVulnerabilities",
        description: "Simple automated vulnerability scan (XSS, SQLi)",
        parameters: {
            type: "object",
            properties: {
                url: { type: "string" },
                scanTypes: { type: "array", items: { type: "string" } }
            },
            required: ["url"]
        }
    }
};

// =========================================
// Tool Implementations
// =========================================

async function handleToolCall(tool, params) {
    switch (tool) {
        case 'sendRequest':
            return await client.createRequest(
                params.url,
                params.method,
                params.headers,
                params.body
            );

        case 'getFindings':
            return await client.getFindings(params.limit);

        case 'getRequestHistory':
            return await client.getRequestHistory(params.limit);

        case 'scanForVulnerabilities':
            return await runSimpleScan(params.url, params.scanTypes || ['xss', 'sqli']);

        case 'getStatus':
            return { status: "connected", mode: "api-adapter" };

        default:
            throw new Error(`Unknown tool: ${tool}`);
    }
}

// Simple Scan Implementation (Client-side orchestration)
async function runSimpleScan(targetUrl, types) {
    const payloads = {
        xss: ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>'],
        sqli: ["' OR '1'='1", "1' ORDER BY 1--"]
    };

    const results = [];

    for (const type of types) {
        if (!payloads[type]) continue;

        for (const payload of payloads[type]) {
            // Inject payload into URL (simple query param injection)
            const u = new URL(targetUrl);
            u.searchParams.forEach((value, key) => {
                u.searchParams.set(key, payload);
            });

            const payloadUrl = u.toString();
            console.log(`[Scan] Testing ${type} on ${payloadUrl}`);

            try {
                await client.createRequest(payloadUrl);
                results.push({ type, payload, status: "sent" });
            } catch (e) {
                results.push({ type, payload, status: "error", error: e.message });
            }
        }
    }

    return {
        success: true,
        scanned: results.length,
        details: results
    };
}

// =========================================
// Server Logic
// =========================================

const server = http.createServer(async (req, res) => {
    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-API-Key");

    if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
    }

    // Auth
    if (req.url !== "/mcp/status") {
        const key = req.headers["x-api-key"];
        if (key !== API_KEY) {
            res.writeHead(401, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Unauthorized" }));
            return;
        }
    }

    try {
        const urlParts = url.parse(req.url, true);

        // GET /mcp/tools
        if (req.method === 'GET' && urlParts.pathname === '/mcp/tools') {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ tools: Object.values(TOOLS) }));
            return;
        }

        // GET /mcp/status
        if (req.method === 'GET' && urlParts.pathname === '/mcp/status') {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ status: "running", type: "api-adapter" }));
            return;
        }

        // POST /mcp/call
        if (req.method === 'POST' && urlParts.pathname === '/mcp/call') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', async () => {
                try {
                    const { tool, params } = JSON.parse(body);
                    if (!tool) throw new Error("Missing tool name");

                    console.log(`[MCP] Executing ${tool}...`);
                    const result = await handleToolCall(tool, params || {});

                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({ success: true, data: result }));
                } catch (e) {
                    console.error(`[MCP] Error:`, e);
                    res.writeHead(500, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({ success: false, error: e.message }));
                }
            });
            return;
        }

        res.writeHead(404);
        res.end();

    } catch (err) {
        console.error(err);
        res.writeHead(500);
        res.end();
    }
});

server.listen(PORT, () => {
    console.log(`Caido MCP API Server running on port ${PORT}`);
    console.log(`Targeting Caido at: ${client.CAIDO_URL || 'default'}`);
});
