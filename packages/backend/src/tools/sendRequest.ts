// =========================================
// MCP Tool: sendRequest
// =========================================
// Send custom HTTP requests through Caido

import type { SDK } from "caido:plugin";
import { RequestSpec } from "caido:plugin";
import { isTargetAllowed } from "../state";

export interface SendRequestInput {
    url: string;
    method?: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";
    headers?: Record<string, string>;
    body?: string;
    followRedirects?: boolean;
}

export interface SendRequestOutput {
    success: boolean;
    error?: string;
    response?: {
        statusCode: number;
        headers: Record<string, string>;
        body: string;
        responseTime: number;
        size: number;
    };
}

export async function sendRequest(
    sdk: SDK,
    input: SendRequestInput
): Promise<SendRequestOutput> {
    const startTime = Date.now();

    // Validate URL
    if (!input.url) {
        return {
            success: false,
            error: "URL is required",
        };
    }

    // Check if target is allowed
    if (!isTargetAllowed(input.url)) {
        return {
            success: false,
            error: `Target not allowed. Add the domain to allowed targets first.`,
        };
    }

    try {
        // Parse URL
        const parsed = new URL(input.url);

        // Build request spec
        const requestSpec = new RequestSpec(input.url);
        requestSpec.setMethod(input.method || "GET");

        // Add headers
        if (input.headers) {
            for (const [name, value] of Object.entries(input.headers)) {
                requestSpec.setHeader(name, value);
            }
        }

        // Add body
        if (input.body) {
            requestSpec.setBody(input.body);
        }

        sdk.console.log(`[MCP] Sending ${input.method || "GET"} request to ${input.url}`);

        // Send request
        const reqResponse = await sdk.requests.send(requestSpec);

        const endTime = Date.now();
        const responseTime = endTime - startTime;

        // Extract response data
        const response = reqResponse.response;
        const responseBody = response.getBody()?.toText() || "";
        const responseHeaders: Record<string, string> = {};

        // Get headers
        const headersList = response.getHeaders();
        for (const header of headersList) {
            responseHeaders[header.name] = header.value;
        }

        return {
            success: true,
            response: {
                statusCode: response.getCode(),
                headers: responseHeaders,
                body: responseBody,
                responseTime,
                size: responseBody.length,
            },
        };
    } catch (error) {
        sdk.console.error(`[MCP] Request failed: ${error}`);
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}
