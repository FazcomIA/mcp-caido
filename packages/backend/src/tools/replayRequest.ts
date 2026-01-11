// =========================================
// MCP Tool: replayRequest
// =========================================
// Replay requests with optional modifications

import type { SDK } from "caido:plugin";
import { RequestSpec } from "caido:plugin";
import { isTargetAllowed } from "../state";

// Delay helper
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface ReplayModifications {
    url?: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    bodyReplace?: { search: string; replace: string }[];
}

export interface ReplayRequestInput {
    requestId: string;
    modifications?: ReplayModifications;
    times?: number;
}

export interface ReplayResult {
    iteration: number;
    statusCode: number;
    responseTime: number;
    bodyLength: number;
    success: boolean;
    error?: string;
}

export interface ReplayRequestOutput {
    success: boolean;
    error?: string;
    originalRequestId: string;
    iterations: number;
    results: ReplayResult[];
}

export async function replayRequest(
    sdk: SDK,
    input: ReplayRequestInput
): Promise<ReplayRequestOutput> {
    const results: ReplayResult[] = [];

    // Validate input
    if (!input.requestId) {
        return {
            success: false,
            error: "requestId is required",
            originalRequestId: "",
            iterations: 0,
            results: [],
        };
    }

    const times = input.times || 1;
    const modifications = input.modifications || {};

    sdk.console.log(`[MCP] Replaying request ${input.requestId} ${times} time(s)`);

    try {
        // Get original request
        const original = await sdk.requests.get(input.requestId);

        if (!original) {
            return {
                success: false,
                error: `Request ${input.requestId} not found`,
                originalRequestId: input.requestId,
                iterations: 0,
                results: [],
            };
        }

        const { request } = original;

        // Build URL
        let url = modifications.url || `https://${request.getHost()}${request.getPath()}`;
        const query = request.getQuery();
        if (query && !modifications.url) {
            url += `?${query}`;
        }

        // Check if target is allowed
        if (!isTargetAllowed(url)) {
            return {
                success: false,
                error: "Target not allowed. Add the domain to allowed targets first.",
                originalRequestId: input.requestId,
                iterations: 0,
                results: [],
            };
        }

        // Get original headers
        const originalHeaders: Record<string, string> = {};
        for (const header of request.getHeaders()) {
            originalHeaders[header.name] = header.value;
        }

        // Get original body
        let body = request.getBody()?.toText() || "";

        // Apply body replacements
        if (modifications.bodyReplace) {
            for (const replacement of modifications.bodyReplace) {
                body = body.replace(new RegExp(replacement.search, "g"), replacement.replace);
            }
        }

        // Override body if provided
        if (modifications.body !== undefined) {
            body = modifications.body;
        }

        // Execute replays
        for (let i = 1; i <= times; i++) {
            try {
                const startTime = Date.now();

                // Build request
                const requestSpec = new RequestSpec(url);
                requestSpec.setMethod(
                    (modifications.method || request.getMethod()) as any
                );

                // Set headers (original + modifications)
                const finalHeaders = { ...originalHeaders, ...modifications.headers };
                for (const [name, value] of Object.entries(finalHeaders)) {
                    if (name.toLowerCase() !== "host" && name.toLowerCase() !== "content-length") {
                        requestSpec.setHeader(name, value);
                    }
                }

                // Set body
                if (body) {
                    requestSpec.setBody(body);
                }

                // Send request
                const response = await sdk.requests.send(requestSpec);
                const responseTime = Date.now() - startTime;

                results.push({
                    iteration: i,
                    statusCode: response.response.getCode(),
                    responseTime,
                    bodyLength: response.response.getBody()?.toText().length || 0,
                    success: true,
                });

                sdk.console.log(`[MCP] Replay ${i}/${times} - Status: ${response.response.getCode()}`);
            } catch (reqError) {
                results.push({
                    iteration: i,
                    statusCode: 0,
                    responseTime: 0,
                    bodyLength: 0,
                    success: false,
                    error: reqError instanceof Error ? reqError.message : String(reqError),
                });
            }

            // Delay between iterations
            if (i < times) {
                await delay(200);
            }
        }

        sdk.console.log(`[MCP] Replay complete. ${results.filter((r) => r.success).length}/${times} successful.`);

        return {
            success: true,
            originalRequestId: input.requestId,
            iterations: times,
            results,
        };
    } catch (error) {
        sdk.console.error(`[MCP] Replay failed: ${error}`);
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
            originalRequestId: input.requestId,
            iterations: 0,
            results,
        };
    }
}
