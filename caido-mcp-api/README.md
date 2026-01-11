# Caido MCP API Server

Este é um servidor MCP standalone que se conecta diretamente à API do Caido.

## Configuração

O arquivo `.env` já deve conter:
```env
CAIDO_URL=http://127.0.0.1:8080/graphql
CAIDO_API_TOKEN=seu_token_aqui
```

## Como Rodar

```bash
cd caido-mcp-api
npm install
node server.js
```

O servidor iniciará na porta `3000`.

## Ferramentas Disponíveis

| Ferramenta | Descrição |
|------------|-----------|
| `sendRequest` | Envia request via Caido |
| `getFindings` | Lista vulnerabilidades |
| `getRequestHistory` | Lista histórico |
| `scanForVulnerabilities` | Automação básica de scan |

## Integração com IA

Use a URL `http://localhost:3000/mcp/call` para interagir com o servidor via seus agentes de IA.
Header necessário: `X-API-Key: mcp-dev-key` (padrão).
