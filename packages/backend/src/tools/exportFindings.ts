// =========================================
// MCP Tool: exportFindings
// =========================================
// Export vulnerabilities in different formats

import type { SDK } from "caido:plugin";

export type ExportFormat = "json" | "csv" | "markdown";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface ExportFindingsInput {
    format?: ExportFormat;
    minSeverity?: Severity;
}

export interface ExportFindingsOutput {
    success: boolean;
    error?: string;
    format: ExportFormat;
    count: number;
    data: string;
}

// Severity order for filtering
const SEVERITY_ORDER: Record<Severity, number> = {
    CRITICAL: 5,
    HIGH: 4,
    MEDIUM: 3,
    LOW: 2,
    INFO: 1,
};

// Convert findings to CSV
function toCSV(findings: any[]): string {
    const headers = ["ID", "Title", "Description", "Reporter", "Host", "Path", "CreatedAt"];
    const rows = findings.map((f) => [
        f.id || "",
        `"${(f.title || "").replace(/"/g, '""')}"`,
        `"${(f.description || "").replace(/"/g, '""').substring(0, 200)}"`,
        f.reporter || "",
        f.host || "",
        f.path || "",
        f.createdAt || "",
    ]);

    return [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
}

// Convert findings to Markdown
function toMarkdown(findings: any[]): string {
    let md = "# Security Findings Report\n\n";
    md += `Generated: ${new Date().toISOString()}\n\n`;
    md += `Total Findings: ${findings.length}\n\n`;
    md += "---\n\n";

    for (const finding of findings) {
        md += `## ${finding.title || "Untitled Finding"}\n\n`;
        md += `- **Reporter:** ${finding.reporter || "Unknown"}\n`;
        md += `- **Host:** ${finding.host || "Unknown"}\n`;
        md += `- **Path:** ${finding.path || "/"}\n`;
        md += `- **Created:** ${finding.createdAt || "Unknown"}\n\n`;

        if (finding.description) {
            md += `### Description\n\n${finding.description}\n\n`;
        }

        md += "---\n\n";
    }

    return md;
}

export async function exportFindings(
    sdk: SDK,
    input: ExportFindingsInput
): Promise<ExportFindingsOutput> {
    const format = input.format || "json";
    const minSeverity = input.minSeverity || "LOW";

    sdk.console.log(`[MCP] Exporting findings in ${format} format`);
    sdk.console.log(`[MCP] Minimum severity: ${minSeverity}`);

    try {
        // Query findings using GraphQL
        const query = `
      query GetFindings {
        findings(first: 100) {
          edges {
            node {
              id
              title
              description
              reporter
              createdAt
              request {
                host
                path
              }
            }
          }
        }
      }
    `;

        const result = await sdk.graphql.query(query, {});

        // Extract findings
        let findings: any[] = [];
        if (result?.findings?.edges) {
            findings = result.findings.edges.map((edge: any) => ({
                id: edge.node.id,
                title: edge.node.title,
                description: edge.node.description,
                reporter: edge.node.reporter,
                createdAt: edge.node.createdAt,
                host: edge.node.request?.host || "",
                path: edge.node.request?.path || "",
            }));
        }

        // Filter by severity if the title contains severity info
        // Note: Caido findings don't have built-in severity, but MCP scanner adds it to titles
        const minSeverityValue = SEVERITY_ORDER[minSeverity];
        findings = findings.filter((f) => {
            // Check if title contains severity
            for (const [sev, val] of Object.entries(SEVERITY_ORDER)) {
                if (f.title?.includes(sev) && val >= minSeverityValue) {
                    return true;
                }
            }
            // Include if no severity found (default include)
            return !Object.keys(SEVERITY_ORDER).some((s) => f.title?.includes(s));
        });

        // Convert to requested format
        let data: string;
        switch (format) {
            case "csv":
                data = toCSV(findings);
                break;
            case "markdown":
                data = toMarkdown(findings);
                break;
            case "json":
            default:
                data = JSON.stringify(findings, null, 2);
                break;
        }

        sdk.console.log(`[MCP] Exported ${findings.length} findings`);

        return {
            success: true,
            format,
            count: findings.length,
            data,
        };
    } catch (error) {
        sdk.console.error(`[MCP] Export failed: ${error}`);
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
            format,
            count: 0,
            data: "",
        };
    }
}
