// =========================================
// MCP Tool: getRequestHistory
// =========================================
// Get history of requests from Caido

import type { SDK } from "caido:plugin";

export interface RequestHistoryFilters {
    method?: string;
    statusCode?: number;
    host?: string;
    path?: string;
}

export interface GetRequestHistoryInput {
    limit?: number;
    filters?: RequestHistoryFilters;
}

export interface RequestHistoryItem {
    id: string;
    host: string;
    path: string;
    method: string;
    query?: string;
    statusCode?: number;
    responseLength?: number;
    createdAt?: string;
}

export interface GetRequestHistoryOutput {
    success: boolean;
    error?: string;
    count: number;
    requests: RequestHistoryItem[];
}

export async function getRequestHistory(
    sdk: SDK,
    input: GetRequestHistoryInput
): Promise<GetRequestHistoryOutput> {
    const limit = Math.min(input.limit || 50, 100); // Max 100
    const filters = input.filters || {};

    sdk.console.log(`[MCP] Getting request history (limit: ${limit})`);

    try {
        // Build query
        let query = sdk.requests.query();

        // Apply limit
        query = query.first(limit);

        // Execute query
        const result = await query.execute();

        // Transform results
        let requests: RequestHistoryItem[] = result.items.map((item) => ({
            id: item.request.getId(),
            host: item.request.getHost(),
            path: item.request.getPath(),
            method: item.request.getMethod(),
            query: item.request.getQuery() || undefined,
            statusCode: item.response?.getCode(),
            responseLength: item.response?.getBody()?.toText().length,
            createdAt: item.request.getCreatedAt().toISOString(),
        }));

        // Apply filters (post-query since SDK query doesn't support all filters)
        if (filters.method) {
            requests = requests.filter(
                (r) => r.method.toLowerCase() === filters.method!.toLowerCase()
            );
        }

        if (filters.statusCode) {
            requests = requests.filter((r) => r.statusCode === filters.statusCode);
        }

        if (filters.host) {
            requests = requests.filter((r) =>
                r.host.toLowerCase().includes(filters.host!.toLowerCase())
            );
        }

        if (filters.path) {
            requests = requests.filter((r) =>
                r.path.toLowerCase().includes(filters.path!.toLowerCase())
            );
        }

        sdk.console.log(`[MCP] Found ${requests.length} requests`);

        return {
            success: true,
            count: requests.length,
            requests,
        };
    } catch (error) {
        sdk.console.error(`[MCP] Failed to get request history: ${error}`);
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
            count: 0,
            requests: [],
        };
    }
}
