# 🛡️ Caido MCP Server Plugin

Plugin para [Caido](https://caido.io) que implementa um servidor **Model Context Protocol (MCP)**, permitindo que agentes de IA (Claude, GPT-4, LangChain) realizem testes de segurança de forma automatizada.

## ✨ Features

- **10 Ferramentas MCP** para testes de segurança
- **Scanner automatizado** de XSS, SQLi, Command Injection, Path Traversal
- **API REST standalone** para integração com Python/LangChain
- **Interface visual** moderna com dark theme
- **Rate limiting** e autenticação via API key
- **Whitelist de alvos** para segurança

## 📦 Instalação

### Requisitos
- [Node.js](https://nodejs.org/) v18+ ou v20+
- [pnpm](https://pnpm.io/) v9+
- [Caido](https://caido.io) instalado

### Build

```bash
cd caido-mcp
pnpm install
pnpm build
```

O plugin será gerado em `dist/plugin_package.zip`.

### Instalar no Caido

1. Abra o Caido
2. Vá em **Plugins** → **Install from file**
3. Selecione `dist/plugin_package.zip`

## 🔧 Ferramentas Disponíveis

| Ferramenta | Descrição |
|------------|-----------|
| `sendRequest` | Enviar requisições HTTP customizadas |
| `scanForVulnerabilities` | Scanner automatizado de vulnerabilidades |
| `analyzeResponse` | Analisar respostas HTTP (headers, dados sensíveis) |
| `fuzzParameter` | Fuzzing de parâmetros com payloads |
| `interceptRequest` | Interceptar e monitorar requisições |
| `checkAuthentication` | Testar bypass de autenticação |
| `exportFindings` | Exportar vulnerabilidades (JSON/CSV/Markdown) |
| `replayRequest` | Repetir requisições com modificações |
| `getRequestHistory` | Obter histórico de requisições |
| `getFindings` | Obter vulnerabilidades encontradas |

## 🌐 API REST (Servidor Standalone)

O servidor MCP pode rodar independente para integração com Python/LangChain:

```bash
cd mcp-server
node server.js
```

O servidor estará disponível em `http://localhost:3000`.

### Endpoints

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/mcp/status` | Status do servidor |
| GET | `/mcp/tools` | Listar ferramentas disponíveis |
| POST | `/mcp/call` | Chamar uma ferramenta |
| POST | `/mcp/targets` | Configurar alvos permitidos |

### Exemplos

**Verificar status:**
```bash
curl http://localhost:3000/mcp/status
```

**Chamar ferramenta:**
```bash
curl -X POST http://localhost:3000/mcp/call \
  -H "Content-Type: application/json" \
  -H "X-API-Key: mcp-dev-key" \
  -d '{
    "tool": "scanForVulnerabilities",
    "params": {
      "url": "https://testphp.vulnweb.com/listproducts.php?cat=1",
      "scanTypes": ["xss", "sqli"]
    }
  }'
```

**Configurar alvos permitidos:**
```bash
curl -X POST http://localhost:3000/mcp/targets \
  -H "Content-Type: application/json" \
  -H "X-API-Key: mcp-dev-key" \
  -d '{"targets": ["testphp.vulnweb.com", "example.com"]}'
```

## 🐍 Integração com Python

```python
import requests

MCP_URL = "http://localhost:3000"
API_KEY = "mcp-dev-key"

def call_mcp_tool(tool: str, params: dict):
    response = requests.post(
        f"{MCP_URL}/mcp/call",
        json={"tool": tool, "params": params},
        headers={"X-API-Key": API_KEY}
    )
    return response.json()

# Exemplo: Executar scan de vulnerabilidades
result = call_mcp_tool("scanForVulnerabilities", {
    "url": "https://testphp.vulnweb.com/listproducts.php?cat=1",
    "scanTypes": ["xss", "sqli"],
    "maxRequests": 50
})

print(f"Vulnerabilidades encontradas: {result['data']['summary']['total']}")
```

## 🔒 Segurança

- **Whitelist obrigatória**: Configure alvos permitidos antes de realizar testes
- **API Key**: Autenticação via header `X-API-Key`
- **Rate Limiting**: 100 requests/minuto por IP
- **Apenas para testes autorizados**: Use somente em ambientes de sua propriedade ou com autorização

## 📁 Estrutura do Projeto

```
caido-mcp/
├── caido.config.ts          # Configuração do plugin
├── package.json
├── pnpm-workspace.yaml
├── packages/
│   ├── backend/src/
│   │   ├── index.ts          # Entry point backend
│   │   ├── state.ts          # Gerenciamento de estado
│   │   ├── tools/            # 10 ferramentas MCP
│   │   └── utils/payloads.ts # Payloads de teste
│   └── frontend/src/
│       ├── index.ts          # Entry point frontend
│       └── styles/main.css   # Estilos
└── mcp-server/
    └── server.js             # Servidor HTTP standalone
```

## 🧪 Ambientes de Teste

Para testes seguros, use ambientes como:

- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [DVWA](https://dvwa.co.uk/)
- [testphp.vulnweb.com](http://testphp.vulnweb.com/)
- [PortSwigger Labs](https://portswigger.net/web-security)

## 📄 Licença

MIT

---

**⚠️ Aviso**: Esta ferramenta é para fins educacionais e testes autorizados apenas. O uso indevido é de responsabilidade do usuário.
