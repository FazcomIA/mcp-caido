# ⚡ Caido MCP Capabilities

Este documento descreve os "superpoderes" desbloqueados com o Caido MCP API, permitindo que agentes de IA e scripts externos controlem o Caido programaticamente.

## 4 Principais Poderes

| Poder | Ferramenta | O que permite fazer? |
| :--- | :--- | :--- |
| **1. Onisciência**<br>*(Visibilidade Total)* | `getRequestHistory` | **Ver tudo que você navega.**<br>Se você usar o proxy do Caido, o MCP pode "ler" o tráfego. Agentes de IA podem analisar seu histórico em tempo real para encontrar chaves de API vazadas, cookies sensíveis ou endpoints interessantes sem você precisar procurar. |
| **2. Telecinesia**<br>*(Ação Remota)* | `sendRequest` | **Forjar qualquer requisição.**<br>O MCP pode enviar requisições HTTP através do motor do Caido. Isso significa que uma IA pode testar endpoints, tentar bypass de login ou enviar payloads, tudo programaticamente. |
| **3. Automação**<br>*(Ataque Automático)* | `scanForVulnerabilities` | **Rodar ataques básicos sozinho.**<br>Implementamos uma lógica que pega uma URL e injeta automaticamente payloads de **XSS** e **SQL Injection** nos parâmetros, reportando o sucesso. |
| **4. Consciência**<br>*(Gestão de Falhas)* | `getFindings` | **Ler relatórios de segurança.**<br>Se o Caido (ou você manualmente) encontrar uma vulnerabilidade e salvar, o MCP consegue ler, permitindo que uma IA gere relatórios ou sugira correções de código baseadas no erro encontrado. |

## 🧠 Integração com IA

Com a API rodando em `http://localhost:3000/mcp/call`, você pode conectar:

*   **Claude / GPT-4:** Para atuarem como Penetesters assistentes.
*   **LangChain / Python:** Para criar scripts de automação complexos.

**Exemplo de Prompt:**
> "Analise o histórico de requisições (`getRequestHistory`) buscando por endpoints que aceitem JSON e tente injetar payloads de SQLi (`scanForVulnerabilities`) neles."
