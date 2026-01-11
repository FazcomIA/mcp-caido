// =========================================
// MCP Server Plugin - Frontend Entry Point
// =========================================
// Creates the plugin page and registers UI components

import type { Caido } from "@caido/sdk-frontend";
import type { API } from "../../backend/src";
import "./styles/main.css";

// Types
interface Target {
    domain: string;
}

interface StatusData {
    success: boolean;
    activeScans: number;
    interceptedRequests: number;
    allowedTargets: string[];
    interceptPatterns: number;
}

// =========================================
// Dashboard Component
// =========================================

function createDashboard(caido: Caido<API>): HTMLElement {
    const container = document.createElement("div");
    container.className = "mcp-dashboard";
    container.innerHTML = `
    <header class="mcp-header">
      <h1>🛡️ MCP Security Server</h1>
      <p class="mcp-subtitle">AI-Powered Security Testing Automation</p>
    </header>

    <div class="mcp-grid">
      <!-- Status Card -->
      <div class="mcp-card mcp-card-status">
        <div class="mcp-card-header">
          <h2>📊 Status</h2>
          <button class="mcp-btn mcp-btn-sm" id="btn-refresh">Refresh</button>
        </div>
        <div class="mcp-card-body">
          <div class="mcp-status-grid">
            <div class="mcp-status-item">
              <span class="mcp-status-label">Connection</span>
              <span class="mcp-status-value mcp-status-connected" id="status-connection">Connected</span>
            </div>
            <div class="mcp-status-item">
              <span class="mcp-status-label">Active Scans</span>
              <span class="mcp-status-value" id="status-scans">0</span>
            </div>
            <div class="mcp-status-item">
              <span class="mcp-status-label">Intercepted</span>
              <span class="mcp-status-value" id="status-intercepted">0</span>
            </div>
            <div class="mcp-status-item">
              <span class="mcp-status-label">Patterns</span>
              <span class="mcp-status-value" id="status-patterns">0</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Targets Card -->
      <div class="mcp-card mcp-card-targets">
        <div class="mcp-card-header">
          <h2>🎯 Allowed Targets</h2>
        </div>
        <div class="mcp-card-body">
          <div class="mcp-input-group">
            <input type="text" id="input-target" placeholder="example.com" class="mcp-input" />
            <button class="mcp-btn mcp-btn-primary" id="btn-add-target">Add</button>
          </div>
          <div class="mcp-targets-list" id="targets-list">
            <p class="mcp-empty">No targets configured. All targets allowed.</p>
          </div>
        </div>
      </div>

      <!-- Quick Actions Card -->
      <div class="mcp-card mcp-card-actions">
        <div class="mcp-card-header">
          <h2>⚡ Quick Actions</h2>
        </div>
        <div class="mcp-card-body">
          <div class="mcp-actions-grid">
            <button class="mcp-action-btn" id="btn-start-scan">
              <span class="mcp-action-icon">🔍</span>
              <span>Start Scan</span>
            </button>
            <button class="mcp-action-btn" id="btn-export">
              <span class="mcp-action-icon">📤</span>
              <span>Export Findings</span>
            </button>
            <button class="mcp-action-btn" id="btn-history">
              <span class="mcp-action-icon">📜</span>
              <span>Request History</span>
            </button>
            <button class="mcp-action-btn" id="btn-findings">
              <span class="mcp-action-icon">🐛</span>
              <span>View Findings</span>
            </button>
          </div>
        </div>
      </div>

      <!-- Tools Card -->
      <div class="mcp-card mcp-card-tools">
        <div class="mcp-card-header">
          <h2>🔧 MCP Tools</h2>
        </div>
        <div class="mcp-card-body">
          <div class="mcp-tools-grid">
            <div class="mcp-tool-item" data-tool="sendRequest">
              <code>sendRequest</code>
              <p>Send custom HTTP requests</p>
            </div>
            <div class="mcp-tool-item" data-tool="scanForVulnerabilities">
              <code>scanForVulnerabilities</code>
              <p>Automated vulnerability scanner</p>
            </div>
            <div class="mcp-tool-item" data-tool="analyzeResponse">
              <code>analyzeResponse</code>
              <p>Analyze HTTP responses</p>
            </div>
            <div class="mcp-tool-item" data-tool="fuzzParameter">
              <code>fuzzParameter</code>
              <p>Fuzz parameters with payloads</p>
            </div>
            <div class="mcp-tool-item" data-tool="interceptRequest">
              <code>interceptRequest</code>
              <p>Intercept and monitor requests</p>
            </div>
            <div class="mcp-tool-item" data-tool="checkAuthentication">
              <code>checkAuthentication</code>
              <p>Test authentication bypass</p>
            </div>
            <div class="mcp-tool-item" data-tool="exportFindings">
              <code>exportFindings</code>
              <p>Export vulnerabilities</p>
            </div>
            <div class="mcp-tool-item" data-tool="replayRequest">
              <code>replayRequest</code>
              <p>Replay requests with modifications</p>
            </div>
            <div class="mcp-tool-item" data-tool="getRequestHistory">
              <code>getRequestHistory</code>
              <p>Get request history</p>
            </div>
            <div class="mcp-tool-item" data-tool="getFindings">
              <code>getFindings</code>
              <p>Get vulnerabilities</p>
            </div>
          </div>
        </div>
      </div>

      <!-- Results Card -->
      <div class="mcp-card mcp-card-results">
        <div class="mcp-card-header">
          <h2>📋 Results</h2>
          <button class="mcp-btn mcp-btn-sm" id="btn-clear-results">Clear</button>
        </div>
        <div class="mcp-card-body">
          <div class="mcp-results-area" id="results-area">
            <p class="mcp-empty">No results yet. Run a tool to see results here.</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Modal Overlay -->
    <div class="mcp-modal-overlay" id="modal-overlay">
      <div class="mcp-modal" id="modal">
        <div class="mcp-modal-header">
          <h3 id="modal-title">Modal Title</h3>
          <button class="mcp-modal-close" id="modal-close">&times;</button>
        </div>
        <div class="mcp-modal-body" id="modal-body">
          <!-- Dynamic content -->
        </div>
        <div class="mcp-modal-footer">
          <button class="mcp-btn mcp-btn-secondary" id="modal-cancel">Cancel</button>
          <button class="mcp-btn mcp-btn-primary" id="modal-submit">Submit</button>
        </div>
      </div>
    </div>
  `;

    // Initialize event handlers
    initializeEventHandlers(container, caido);

    // Load initial status
    refreshStatus(container, caido);

    return container;
}

// =========================================
// Event Handlers
// =========================================

function initializeEventHandlers(container: HTMLElement, caido: Caido<API>): void {
    // Refresh Status
    const btnRefresh = container.querySelector("#btn-refresh");
    btnRefresh?.addEventListener("click", () => refreshStatus(container, caido));

    // Add Target
    const btnAddTarget = container.querySelector("#btn-add-target");
    const inputTarget = container.querySelector("#input-target") as HTMLInputElement;
    btnAddTarget?.addEventListener("click", async () => {
        const target = inputTarget?.value.trim();
        if (target) {
            await addTarget(container, caido, target);
            inputTarget.value = "";
        }
    });

    // Enter key for target input
    inputTarget?.addEventListener("keypress", async (e) => {
        if (e.key === "Enter") {
            const target = inputTarget.value.trim();
            if (target) {
                await addTarget(container, caido, target);
                inputTarget.value = "";
            }
        }
    });

    // Quick Actions
    container.querySelector("#btn-start-scan")?.addEventListener("click", () => {
        showScanModal(container, caido);
    });

    container.querySelector("#btn-export")?.addEventListener("click", async () => {
        await exportFindings(container, caido);
    });

    container.querySelector("#btn-history")?.addEventListener("click", async () => {
        await showRequestHistory(container, caido);
    });

    container.querySelector("#btn-findings")?.addEventListener("click", async () => {
        await showFindings(container, caido);
    });

    // Clear Results
    container.querySelector("#btn-clear-results")?.addEventListener("click", () => {
        const resultsArea = container.querySelector("#results-area");
        if (resultsArea) {
            resultsArea.innerHTML = '<p class="mcp-empty">No results yet. Run a tool to see results here.</p>';
        }
    });

    // Modal Close
    container.querySelector("#modal-close")?.addEventListener("click", () => {
        closeModal(container);
    });

    container.querySelector("#modal-cancel")?.addEventListener("click", () => {
        closeModal(container);
    });

    container.querySelector("#modal-overlay")?.addEventListener("click", (e) => {
        if (e.target === container.querySelector("#modal-overlay")) {
            closeModal(container);
        }
    });

    // Tool Items
    container.querySelectorAll(".mcp-tool-item").forEach((item) => {
        item.addEventListener("click", () => {
            const tool = (item as HTMLElement).dataset.tool;
            if (tool) {
                showToolModal(container, caido, tool);
            }
        });
    });
}

// =========================================
// API Functions
// =========================================

async function refreshStatus(container: HTMLElement, caido: Caido<API>): Promise<void> {
    try {
        const status = await caido.backend.getStatus();

        if (status.success) {
            container.querySelector("#status-scans")!.textContent = String(status.activeScans);
            container.querySelector("#status-intercepted")!.textContent = String(status.interceptedRequests);
            container.querySelector("#status-patterns")!.textContent = String(status.interceptPatterns);

            updateTargetsList(container, status.allowedTargets);
        }
    } catch (error) {
        console.error("[MCP Frontend] Failed to get status:", error);
        container.querySelector("#status-connection")!.textContent = "Error";
        container.querySelector("#status-connection")!.classList.remove("mcp-status-connected");
        container.querySelector("#status-connection")!.classList.add("mcp-status-error");
    }
}

async function addTarget(container: HTMLElement, caido: Caido<API>, target: string): Promise<void> {
    try {
        const status = await caido.backend.getStatus();
        const currentTargets = status.allowedTargets || [];
        const newTargets = [...currentTargets, target];

        const result = await caido.backend.setAllowedTargets(newTargets);

        if (result.success) {
            updateTargetsList(container, result.allowedTargets);
        }
    } catch (error) {
        console.error("[MCP Frontend] Failed to add target:", error);
        showResult(container, { error: "Failed to add target" });
    }
}

function updateTargetsList(container: HTMLElement, targets: string[]): void {
    const targetsList = container.querySelector("#targets-list");
    if (!targetsList) return;

    if (targets.length === 0) {
        targetsList.innerHTML = '<p class="mcp-empty">No targets configured. All targets allowed.</p>';
    } else {
        targetsList.innerHTML = targets
            .map(
                (t) => `
        <div class="mcp-target-tag">
          <span>${t}</span>
          <button class="mcp-target-remove" data-target="${t}">&times;</button>
        </div>
      `
            )
            .join("");

        // Add remove handlers
        targetsList.querySelectorAll(".mcp-target-remove").forEach((btn) => {
            btn.addEventListener("click", async (e) => {
                const target = (e.target as HTMLElement).closest(".mcp-target-remove")?.getAttribute("data-target");
                if (target) {
                    const newTargets = targets.filter((t) => t !== target);
                    // This would need the caido instance, simplified for now
                }
            });
        });
    }
}

// =========================================
// Modal Functions
// =========================================

function showModal(container: HTMLElement, title: string, body: string): void {
    const overlay = container.querySelector("#modal-overlay") as HTMLElement;
    const modalTitle = container.querySelector("#modal-title") as HTMLElement;
    const modalBody = container.querySelector("#modal-body") as HTMLElement;

    modalTitle.textContent = title;
    modalBody.innerHTML = body;
    overlay.classList.add("mcp-modal-visible");
}

function closeModal(container: HTMLElement): void {
    const overlay = container.querySelector("#modal-overlay") as HTMLElement;
    overlay.classList.remove("mcp-modal-visible");
}

function showScanModal(container: HTMLElement, caido: Caido<API>): void {
    const body = `
    <div class="mcp-form">
      <div class="mcp-form-group">
        <label>Target URL</label>
        <input type="text" id="scan-url" class="mcp-input" placeholder="https://example.com/page?param=value" />
      </div>
      <div class="mcp-form-group">
        <label>Scan Types</label>
        <div class="mcp-checkbox-group">
          <label><input type="checkbox" value="xss" checked /> XSS</label>
          <label><input type="checkbox" value="sqli" checked /> SQL Injection</label>
          <label><input type="checkbox" value="command_injection" checked /> Command Injection</label>
          <label><input type="checkbox" value="path_traversal" checked /> Path Traversal</label>
        </div>
      </div>
      <div class="mcp-form-group">
        <label>Max Requests</label>
        <input type="number" id="scan-max" class="mcp-input" value="50" min="1" max="500" />
      </div>
    </div>
  `;

    showModal(container, "🔍 Start Vulnerability Scan", body);

    // Attach submit handler
    const submitBtn = container.querySelector("#modal-submit") as HTMLButtonElement;
    submitBtn.onclick = async () => {
        const url = (container.querySelector("#scan-url") as HTMLInputElement)?.value;
        const maxRequests = parseInt((container.querySelector("#scan-max") as HTMLInputElement)?.value || "50");
        const scanTypes: string[] = [];

        container.querySelectorAll(".mcp-checkbox-group input:checked").forEach((cb) => {
            scanTypes.push((cb as HTMLInputElement).value);
        });

        if (!url) {
            alert("Please enter a URL");
            return;
        }

        closeModal(container);
        showResult(container, { message: "Scan started...", loading: true });

        try {
            const result = await caido.backend.scanForVulnerabilities({
                url,
                scanTypes: scanTypes as any,
                maxRequests,
            });

            showResult(container, result);
        } catch (error: any) {
            showResult(container, { error: error.message });
        }
    };
}

function showToolModal(container: HTMLElement, caido: Caido<API>, tool: string): void {
    // Generic tool modal - can be extended for each tool
    const body = `
    <div class="mcp-form">
      <p>Configure and run the <code>${tool}</code> tool.</p>
      <div class="mcp-form-group">
        <label>Parameters (JSON)</label>
        <textarea id="tool-params" class="mcp-textarea" rows="5">{}</textarea>
      </div>
    </div>
  `;

    showModal(container, `🔧 ${tool}`, body);

    const submitBtn = container.querySelector("#modal-submit") as HTMLButtonElement;
    submitBtn.onclick = async () => {
        try {
            const paramsStr = (container.querySelector("#tool-params") as HTMLTextAreaElement)?.value || "{}";
            const params = JSON.parse(paramsStr);

            closeModal(container);
            showResult(container, { message: `Running ${tool}...`, loading: true });

            // Call the tool dynamically
            const backendFn = (caido.backend as any)[tool];
            if (typeof backendFn === "function") {
                const result = await backendFn(params);
                showResult(container, result);
            } else {
                showResult(container, { error: `Tool ${tool} not found` });
            }
        } catch (error: any) {
            showResult(container, { error: error.message });
        }
    };
}

async function exportFindings(container: HTMLElement, caido: Caido<API>): Promise<void> {
    showResult(container, { message: "Exporting findings...", loading: true });

    try {
        const result = await caido.backend.exportFindings({ format: "json" });
        showResult(container, result);
    } catch (error: any) {
        showResult(container, { error: error.message });
    }
}

async function showRequestHistory(container: HTMLElement, caido: Caido<API>): Promise<void> {
    showResult(container, { message: "Loading request history...", loading: true });

    try {
        const result = await caido.backend.getRequestHistory({ limit: 20 });
        showResult(container, result);
    } catch (error: any) {
        showResult(container, { error: error.message });
    }
}

async function showFindings(container: HTMLElement, caido: Caido<API>): Promise<void> {
    showResult(container, { message: "Loading findings...", loading: true });

    try {
        const result = await caido.backend.getFindings({ limit: 20 });
        showResult(container, result);
    } catch (error: any) {
        showResult(container, { error: error.message });
    }
}

// =========================================
// Result Display
// =========================================

function showResult(container: HTMLElement, result: any): void {
    const resultsArea = container.querySelector("#results-area");
    if (!resultsArea) return;

    if (result.loading) {
        resultsArea.innerHTML = `
      <div class="mcp-loading">
        <span class="mcp-spinner"></span>
        <span>${result.message || "Loading..."}</span>
      </div>
    `;
        return;
    }

    if (result.error) {
        resultsArea.innerHTML = `
      <div class="mcp-result-error">
        <strong>Error:</strong> ${result.error}
      </div>
    `;
        return;
    }

    // Format result based on type
    if (result.findings) {
        resultsArea.innerHTML = formatFindingsResult(result);
    } else if (result.requests) {
        resultsArea.innerHTML = formatRequestsResult(result);
    } else if (result.summary) {
        resultsArea.innerHTML = formatScanResult(result);
    } else {
        resultsArea.innerHTML = `
      <pre class="mcp-result-json">${JSON.stringify(result, null, 2)}</pre>
    `;
    }
}

function formatScanResult(result: any): string {
    const { summary, findings = [] } = result;

    return `
    <div class="mcp-scan-result">
      <div class="mcp-severity-summary">
        <div class="mcp-severity-item mcp-severity-critical">
          <span class="mcp-severity-count">${summary?.critical || 0}</span>
          <span class="mcp-severity-label">Critical</span>
        </div>
        <div class="mcp-severity-item mcp-severity-high">
          <span class="mcp-severity-count">${summary?.high || 0}</span>
          <span class="mcp-severity-label">High</span>
        </div>
        <div class="mcp-severity-item mcp-severity-medium">
          <span class="mcp-severity-count">${summary?.medium || 0}</span>
          <span class="mcp-severity-label">Medium</span>
        </div>
        <div class="mcp-severity-item mcp-severity-low">
          <span class="mcp-severity-count">${summary?.low || 0}</span>
          <span class="mcp-severity-label">Low</span>
        </div>
      </div>
      <div class="mcp-findings-list">
        ${findings.length === 0 ? '<p class="mcp-empty">No vulnerabilities found.</p>' : ""}
        ${findings.map((f: any) => `
          <div class="mcp-finding-item mcp-finding-${f.severity?.toLowerCase() || 'medium'}">
            <strong>${f.title}</strong>
            <p>${f.description || ""}</p>
            <code>${f.url || ""}</code>
            ${f.evidence ? `<small>Evidence: ${f.evidence}</small>` : ""}
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

function formatRequestsResult(result: any): string {
    const { requests = [] } = result;

    return `
    <div class="mcp-requests-result">
      <table class="mcp-table">
        <thead>
          <tr>
            <th>Method</th>
            <th>Host</th>
            <th>Path</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${requests.map((r: any) => `
            <tr>
              <td><span class="mcp-method mcp-method-${r.method?.toLowerCase()}">${r.method}</span></td>
              <td>${r.host}</td>
              <td>${r.path}</td>
              <td><span class="mcp-status-code mcp-status-${Math.floor((r.statusCode || 0) / 100)}xx">${r.statusCode || "?"}</span></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function formatFindingsResult(result: any): string {
    const { findings = [] } = result;

    if (findings.length === 0) {
        return '<p class="mcp-empty">No findings found.</p>';
    }

    return `
    <div class="mcp-findings-result">
      ${findings.map((f: any) => `
        <div class="mcp-finding-card">
          <h4>${f.title}</h4>
          <p>${f.description || "No description"}</p>
          <div class="mcp-finding-meta">
            <span>Reporter: ${f.reporter}</span>
            <span>Host: ${f.host || "?"}</span>
          </div>
        </div>
      `).join("")}
    </div>
  `;
}

// =========================================
// Plugin Initialization
// =========================================

export const init = (caido: Caido<API>) => {
    // Register the main page
    caido.navigation.addPage("/mcp-server", {
        body: createDashboard(caido),
    });

    // Add to sidebar
    caido.sidebar.registerItem("MCP Server", "/mcp-server", {
        icon: "shield",
    });

    // Register commands
    caido.commands.register("mcp:refresh", {
        name: "MCP: Refresh Status",
        run: () => {
            // Trigger refresh
            document.querySelector("#btn-refresh")?.dispatchEvent(new Event("click"));
        },
    });

    caido.commands.register("mcp:scan", {
        name: "MCP: Start Scan",
        run: () => {
            document.querySelector("#btn-start-scan")?.dispatchEvent(new Event("click"));
        },
    });

    console.log("[MCP Frontend] Initialized");
};
