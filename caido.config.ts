import { defineConfig } from "@caido-community/plugin-builder";

export default defineConfig({
  id: "caido-mcp-server",
  name: "MCP Server",
  description: "Model Context Protocol server for AI-powered security testing automation",
  version: "1.0.0",
  author: {
    name: "Caido MCP",
    email: "mcp@caido.io",
    url: "https://github.com/caido-mcp",
  },
  plugins: [
    {
      kind: "backend",
      id: "mcp-backend",
      name: "MCP Backend",
      root: "packages/backend",
      entrypoint: "src/index.ts",
    },
    {
      kind: "frontend",
      id: "mcp-frontend", 
      name: "MCP Frontend",
      root: "packages/frontend",
      entrypoint: "src/index.ts",
      backend: "mcp-backend",
      style: "src/styles/main.css",
    },
  ],
});
