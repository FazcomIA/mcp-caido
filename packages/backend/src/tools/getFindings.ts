// =========================================
// MCP Tool: getFindings
// =========================================
// Get vulnerabilities/findings from Caido

import type { SDK } from "caido:plugin";

export interface GetFindingsInput {
    severity?: string;
    reporter?: string;
    limit?: number;
}

export interface FindingItem {
    id: string;
    title: string;
    description?: string;
    reporter: string;
    host?: string;
    path?: string;
    createdAt: string;
}

export interface GetFindingsOutput {
    success: boolean;
    error?: string;
    count: number;
    findings: FindingItem[];
}

export async function getFindings(
    sdk: SDK,
    input: GetFindingsInput
): Promise<GetFindingsOutput> {
    const limit = Math.min(input.limit || 50, 100);

    sdk.console.log(`[MCP] Getting findings (limit: ${limit})`);

    try {
        // Query findings using GraphQL
        const query = `
      query GetFindings($first: Int) {
        findings(first: $first) {
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

        const result = await sdk.graphql.query(query, { first: limit });

        // Extract findings
        let findings: FindingItem[] = [];
        if (result?.findings?.edges) {
            findings = result.findings.edges.map((edge: any) => ({
                id: edge.node.id,
                title: edge.node.title,
                description: edge.node.description,
                reporter: edge.node.reporter,
                host: edge.node.request?.host,
                path: edge.node.request?.path,
                createdAt: edge.node.createdAt,
            }));
        }

        // Apply filters
        if (input.reporter) {
            findings = findings.filter((f) =>
                f.reporter.toLowerCase().includes(input.reporter!.toLowerCase())
            );
        }

        if (input.severity) {
            findings = findings.filter((f) =>
                f.title.toLowerCase().includes(input.severity!.toLowerCase())
            );
        }

        sdk.console.log(`[MCP] Found ${findings.length} findings`);

        return {
            success: true,
            count: findings.length,
            findings,
        };
    } catch (error) {
        sdk.console.error(`[MCP] Failed to get findings: ${error}`);
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
            count: 0,
            findings: [],
        };
    }
}
