// =========================================
// MCP Tool: interceptRequest
// =========================================
// Intercept and monitor requests in real-time

import type { SDK } from "caido:plugin";
import {
    addInterceptPattern,
    removeInterceptPattern,
    getInterceptPatterns,
    addInterceptedRequest,
    getInterceptedRequests,
} from "../state";

export interface InterceptRequestInput {
    pattern: string; // Regex pattern to match URLs
    modifications?: {
        headers?: Record<string, string>;
        body?: string;
        method?: string;
    };
    enabled?: boolean;
}

export interface InterceptRequestOutput {
    success: boolean;
    error?: string;
    interceptId?: string;
    message?: string;
}

export interface GetInterceptedOutput {
    success: boolean;
    interceptId?: string;
    requests: {
        id: string;
        timestamp: number;
        host: string;
        path: string;
        method: string;
        matched: boolean;
    }[];
}

// Generate unique ID
const generateId = () => Math.random().toString(36).substring(2, 15);

// Register intercept pattern
export async function interceptRequest(
    sdk: SDK,
    input: InterceptRequestInput
): Promise<InterceptRequestOutput> {
    // Validate input
    if (!input.pattern) {
        return {
            success: false,
            error: "Pattern is required",
        };
    }

    // Validate regex
    try {
        new RegExp(input.pattern, "i");
    } catch (error) {
        return {
            success: false,
            error: `Invalid regex pattern: ${error}`,
        };
    }

    const interceptId = generateId();
    const enabled = input.enabled !== false;

    sdk.console.log(`[MCP] Registering intercept pattern: ${input.pattern}`);

    // Add pattern to state
    addInterceptPattern(
        interceptId,
        input.pattern,
        input.modifications || {},
        enabled
    );

    // Register event listener (note: this is called once at init, pattern matching is done in state)
    sdk.console.log(`[MCP] Intercept registered with ID: ${interceptId}`);

    return {
        success: true,
        interceptId,
        message: `Intercept pattern registered: ${input.pattern}`,
    };
}

// Stop intercepting (remove pattern)
export interface StopInterceptInput {
    interceptId: string;
}

export async function stopIntercept(
    sdk: SDK,
    input: StopInterceptInput
): Promise<InterceptRequestOutput> {
    if (!input.interceptId) {
        return {
            success: false,
            error: "interceptId is required",
        };
    }

    const removed = removeInterceptPattern(input.interceptId);

    if (!removed) {
        return {
            success: false,
            error: `Intercept ID ${input.interceptId} not found`,
        };
    }

    sdk.console.log(`[MCP] Intercept removed: ${input.interceptId}`);

    return {
        success: true,
        interceptId: input.interceptId,
        message: "Intercept pattern removed",
    };
}

// Get intercepted requests
export interface GetInterceptedInput {
    limit?: number;
}

export async function getIntercepted(
    sdk: SDK,
    input: GetInterceptedInput
): Promise<GetInterceptedOutput> {
    const limit = input.limit || 50;
    const requests = getInterceptedRequests().slice(0, limit);

    sdk.console.log(`[MCP] Returning ${requests.length} intercepted requests`);

    return {
        success: true,
        requests,
    };
}

// List active intercept patterns
export interface ListInterceptPatternsOutput {
    success: boolean;
    patterns: {
        id: string;
        pattern: string;
        enabled: boolean;
        modifications: { headers?: Record<string, string>; body?: string; method?: string };
    }[];
}

export async function listInterceptPatterns(
    sdk: SDK
): Promise<ListInterceptPatternsOutput> {
    const patterns = getInterceptPatterns().map((p) => ({
        id: p.id,
        pattern: p.pattern,
        enabled: p.enabled,
        modifications: p.modifications,
    }));

    return {
        success: true,
        patterns,
    };
}

// Initialize intercept event handler
export function initInterceptHandler(sdk: SDK): void {
    sdk.events.onInterceptRequest((sdk, request) => {
        const host = request.getHost();
        const path = request.getPath();
        const method = request.getMethod();
        const url = `${host}${path}`;

        // Check against all patterns
        const patterns = getInterceptPatterns();
        let matched = false;

        for (const pattern of patterns) {
            if (!pattern.enabled) continue;

            if (pattern.regex.test(url)) {
                matched = true;
                sdk.console.log(`[MCP] Request matched pattern: ${pattern.pattern}`);
                break;
            }
        }

        // Store intercepted request
        addInterceptedRequest({
            id: request.getId(),
            timestamp: Date.now(),
            host,
            path,
            method,
            matched,
        });
    });

    sdk.console.log("[MCP] Intercept handler initialized");
}
