// =========================================
// MCP Tool: fuzzParameter
// =========================================
// Fuzzing specific parameters with custom payloads

import type { SDK } from "caido:plugin";
import { RequestSpec } from "caido:plugin";
import { isTargetAllowed } from "../state";

// Delay helper
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface FuzzParameterInput {
    url: string;
    parameter: string;
    payloads: string[];
    method?: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
    maxRequests?: number;
    inBody?: boolean; // Fuzz in body instead of URL params
    contentType?: string;
}

export interface FuzzResult {
    payload: string;
    statusCode: number;
    responseTime: number;
    bodyLength: number;
    interesting: boolean;
    reason?: string;
}

export interface FuzzParameterOutput {
    success: boolean;
    error?: string;
    parameter: string;
    totalRequests: number;
    interestingResponses: number;
    results: FuzzResult[];
    summary: {
        avgResponseTime: number;
        avgBodyLength: number;
        statusCodes: Record<number, number>;
    };
}

// Determine if response is interesting
function isInteresting(
    statusCode: number,
    responseTime: number,
    bodyLength: number,
    avgResponseTime: number,
    avgBodyLength: number
): { interesting: boolean; reason?: string } {
    // Interesting status codes
    if (statusCode === 500) {
        return { interesting: true, reason: "Server error (500)" };
    }
    if (statusCode === 403) {
        return { interesting: true, reason: "Forbidden (403) - possible WAF" };
    }
    if (statusCode === 200 && bodyLength > avgBodyLength * 2) {
        return { interesting: true, reason: "Response significantly larger than average" };
    }
    if (responseTime > avgResponseTime * 3) {
        return { interesting: true, reason: "Response significantly slower than average" };
    }
    if (statusCode !== 404 && statusCode !== 400 && statusCode !== 200) {
        return { interesting: true, reason: `Unexpected status code: ${statusCode}` };
    }

    return { interesting: false };
}

// Inject payload into URL parameter
function injectPayloadInUrlParam(
    url: string,
    parameter: string,
    payload: string
): string {
    try {
        const parsed = new URL(url);
        parsed.searchParams.set(parameter, payload);
        return parsed.toString();
    } catch {
        return `${url}?${parameter}=${encodeURIComponent(payload)}`;
    }
}

// Build body with payload
function buildBody(
    parameter: string,
    payload: string,
    contentType?: string
): string {
    if (contentType?.includes("application/json")) {
        return JSON.stringify({ [parameter]: payload });
    }
    return `${parameter}=${encodeURIComponent(payload)}`;
}

export async function fuzzParameter(
    sdk: SDK,
    input: FuzzParameterInput
): Promise<FuzzParameterOutput> {
    // Validate input
    if (!input.url) {
        return {
            success: false,
            error: "URL is required",
            parameter: input.parameter || "",
            totalRequests: 0,
            interestingResponses: 0,
            results: [],
            summary: { avgResponseTime: 0, avgBodyLength: 0, statusCodes: {} },
        };
    }

    if (!input.parameter) {
        return {
            success: false,
            error: "Parameter name is required",
            parameter: "",
            totalRequests: 0,
            interestingResponses: 0,
            results: [],
            summary: { avgResponseTime: 0, avgBodyLength: 0, statusCodes: {} },
        };
    }

    if (!input.payloads || input.payloads.length === 0) {
        return {
            success: false,
            error: "At least one payload is required",
            parameter: input.parameter,
            totalRequests: 0,
            interestingResponses: 0,
            results: [],
            summary: { avgResponseTime: 0, avgBodyLength: 0, statusCodes: {} },
        };
    }

    // Check if target is allowed
    if (!isTargetAllowed(input.url)) {
        return {
            success: false,
            error: "Target not allowed. Add the domain to allowed targets first.",
            parameter: input.parameter,
            totalRequests: 0,
            interestingResponses: 0,
            results: [],
            summary: { avgResponseTime: 0, avgBodyLength: 0, statusCodes: {} },
        };
    }

    const method = input.method || "GET";
    const maxRequests = input.maxRequests || 100;
    const results: FuzzResult[] = [];
    const statusCodes: Record<number, number> = {};

    sdk.console.log(`[MCP] Starting fuzzing on parameter: ${input.parameter}`);
    sdk.console.log(`[MCP] URL: ${input.url}`);
    sdk.console.log(`[MCP] Payloads: ${input.payloads.length}`);

    // First pass: collect baseline metrics
    let totalResponseTime = 0;
    let totalBodyLength = 0;
    let requestCount = 0;

    for (const payload of input.payloads.slice(0, maxRequests)) {
        try {
            const startTime = Date.now();

            let requestSpec: RequestSpec;

            if (input.inBody) {
                // Fuzz in body
                requestSpec = new RequestSpec(input.url);
                requestSpec.setMethod(method);
                const contentType = input.contentType || "application/x-www-form-urlencoded";
                requestSpec.setHeader("Content-Type", contentType);
                requestSpec.setBody(buildBody(input.parameter, payload, contentType));
            } else {
                // Fuzz in URL params
                const fuzzedUrl = injectPayloadInUrlParam(input.url, input.parameter, payload);
                requestSpec = new RequestSpec(fuzzedUrl);
                requestSpec.setMethod(method);
            }

            const reqResponse = await sdk.requests.send(requestSpec);
            const responseTime = Date.now() - startTime;

            const statusCode = reqResponse.response.getCode();
            const bodyLength = reqResponse.response.getBody()?.toText().length || 0;

            totalResponseTime += responseTime;
            totalBodyLength += bodyLength;
            requestCount++;

            // Track status codes
            statusCodes[statusCode] = (statusCodes[statusCode] || 0) + 1;

            results.push({
                payload,
                statusCode,
                responseTime,
                bodyLength,
                interesting: false, // Will be updated in second pass
            });

            // Rate limiting
            await delay(100);
        } catch (error) {
            sdk.console.error(`[MCP] Request failed for payload "${payload}": ${error}`);
            results.push({
                payload,
                statusCode: 0,
                responseTime: 0,
                bodyLength: 0,
                interesting: true,
                reason: `Request failed: ${error}`,
            });
        }
    }

    // Calculate averages
    const avgResponseTime = requestCount > 0 ? totalResponseTime / requestCount : 0;
    const avgBodyLength = requestCount > 0 ? totalBodyLength / requestCount : 0;

    // Second pass: identify interesting responses
    let interestingCount = 0;
    for (const result of results) {
        if (result.statusCode === 0) {
            interestingCount++;
            continue; // Already marked as interesting
        }

        const analysis = isInteresting(
            result.statusCode,
            result.responseTime,
            result.bodyLength,
            avgResponseTime,
            avgBodyLength
        );

        result.interesting = analysis.interesting;
        result.reason = analysis.reason;

        if (analysis.interesting) {
            interestingCount++;
        }
    }

    sdk.console.log(`[MCP] Fuzzing complete. ${interestingCount} interesting responses found.`);

    return {
        success: true,
        parameter: input.parameter,
        totalRequests: requestCount,
        interestingResponses: interestingCount,
        results,
        summary: {
            avgResponseTime: Math.round(avgResponseTime),
            avgBodyLength: Math.round(avgBodyLength),
            statusCodes,
        },
    };
}
