# Caido MCP Server

A Model Context Protocol (MCP) server that acts as a bridge to [Caido](https://caido.io/), allowing AI Agents (like Claude, LangChain, etc.) to perform automated security testing and analysis.

## 🚀 Capabilities

This server connects to your local Caido instance (default port `8080`) and exposes tools to:
- **View Request History**: Analyze traffic captured by Caido proxy.
- **Send Requests**: Forge and send HTTP requests via Caido's engine.
- **Scan for Mitigation**: Run basic automated XSS/SQLi checks.
- **Get Findings**: Retrieve reported vulnerabilities.

See [MCP_CAPABILITIES.md](./MCP_CAPABILITIES.md) for a detailed power list.

## 🛠️ Setup

1. **Prerequisites**:
   - Node.js installed.
   - Caido running (usually on port 8080).
   - Caido API Token (Settings -> API).

2. **Installation**:
   ```bash
   git clone https://github.com/FazcomIA/mcp-caido.git
   cd mcp-caido
   npm install
   ```

3. **Configuration**:
   Create a `.env` file in the root:
   ```env
   CAIDO_URL=http://127.0.0.1:8080/graphql
   CAIDO_API_TOKEN=your_token_here
   MCP_PORT=3000
   MCP_API_KEY=mcp-dev-key
   ```

## 🏃 Usage

Start the server:
```bash
node server.js
```

### Connect an AI Agent
The MCP server listens on `http://localhost:3000/mcp/call`.
Required Header: `X-API-Key: mcp-dev-key`

**Example Curl:**
```bash
curl -X POST http://localhost:3000/mcp/call \
  -H "Content-Type: application/json" \
  -H "X-API-Key: mcp-dev-key" \
  -d '{"tool": "getStatus", "params": {}}'
```

## 🔒 Security
- **API Key**: Protected by `MCP_API_KEY`.
- **Local Only**: By default, runs locally. Be careful if exposing to a network.
