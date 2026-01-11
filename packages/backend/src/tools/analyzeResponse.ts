// =========================================
// MCP Tool: analyzeResponse
// =========================================
// Analyze HTTP responses for suspicious patterns, security headers, and sensitive data

import type { SDK } from "caido:plugin";
import {
    SECURITY_HEADERS,
    SENSITIVE_DATA_PATTERNS,
    ERROR_PATTERNS,
} from "../utils/payloads";

export interface AnalyzeResponseInput {
    requestId: string;
    patterns?: string[]; // Custom regex patterns to match
}

export interface SecurityHeaderAnalysis {
    name: string;
    present: boolean;
    value?: string;
    recommendation?: string;
}

export interface SensitiveDataMatch {
    type: string;
    count: number;
    samples: string[];
}

export interface ErrorMatch {
    type: string;
    pattern: string;
    match: string;
}

export interface AnalyzeResponseOutput {
    success: boolean;
    error?: string;
    analysis?: {
        statusCode: number;
        contentType: string;
        contentLength: number;
        suspicious: string[];
        securityHeaders: SecurityHeaderAnalysis[];
        sensitiveData: SensitiveDataMatch[];
        errors: ErrorMatch[];
        customMatches: { pattern: string; matches: string[] }[];
    };
}

// Check security headers
function analyzeSecurityHeaders(
    headers: Record<string, string>
): SecurityHeaderAnalysis[] {
    const analysis: SecurityHeaderAnalysis[] = [];

    for (const headerName of SECURITY_HEADERS) {
        const headerValue = Object.keys(headers).find(
            (h) => h.toLowerCase() === headerName.toLowerCase()
        );

        const result: SecurityHeaderAnalysis = {
            name: headerName,
            present: !!headerValue,
            value: headerValue ? headers[headerValue] : undefined,
        };

        // Add recommendations for missing headers
        if (!result.present) {
            switch (headerName) {
                case "Content-Security-Policy":
                    result.recommendation =
                        "Add CSP header to prevent XSS and data injection attacks";
                    break;
                case "X-Content-Type-Options":
                    result.recommendation =
                        "Add 'nosniff' to prevent MIME type sniffing";
                    break;
                case "X-Frame-Options":
                    result.recommendation = "Add 'DENY' or 'SAMEORIGIN' to prevent clickjacking";
                    break;
                case "Strict-Transport-Security":
                    result.recommendation =
                        "Add HSTS header to enforce HTTPS connections";
                    break;
                case "X-XSS-Protection":
                    result.recommendation =
                        "Add '1; mode=block' for legacy XSS protection";
                    break;
                case "Referrer-Policy":
                    result.recommendation =
                        "Add referrer policy to control referrer information";
                    break;
            }
        }

        analysis.push(result);
    }

    return analysis;
}

// Check for sensitive data
function analyzeSensitiveData(body: string): SensitiveDataMatch[] {
    const matches: SensitiveDataMatch[] = [];

    for (const [type, pattern] of Object.entries(SENSITIVE_DATA_PATTERNS)) {
        const found = body.match(pattern);
        if (found && found.length > 0) {
            // Mask sensitive data for security
            const maskedSamples = found.slice(0, 3).map((sample) => {
                if (sample.length > 8) {
                    return sample.substring(0, 4) + "****" + sample.substring(sample.length - 4);
                }
                return "****";
            });

            matches.push({
                type,
                count: found.length,
                samples: maskedSamples,
            });
        }
    }

    return matches;
}

// Check for error messages
function analyzeErrors(body: string): ErrorMatch[] {
    const matches: ErrorMatch[] = [];

    for (const [type, patterns] of Object.entries(ERROR_PATTERNS)) {
        for (const pattern of patterns) {
            const match = body.match(pattern);
            if (match) {
                matches.push({
                    type,
                    pattern: pattern.toString(),
                    match: match[0].substring(0, 200), // Limit length
                });
            }
        }
    }

    return matches;
}

// Detect suspicious patterns
function detectSuspicious(
    statusCode: number,
    headers: Record<string, string>,
    body: string
): string[] {
    const suspicious: string[] = [];

    // Check status code
    if (statusCode >= 500) {
        suspicious.push(`Server error detected (${statusCode})`);
    }

    // Check for directory listing
    if (body.includes("Index of /") || body.includes("Directory listing")) {
        suspicious.push("Directory listing enabled");
    }

    // Check for server info disclosure
    const serverHeader = Object.keys(headers).find(
        (h) => h.toLowerCase() === "server"
    );
    if (serverHeader && headers[serverHeader]) {
        suspicious.push(`Server header disclosure: ${headers[serverHeader]}`);
    }

    // Check for X-Powered-By
    const poweredBy = Object.keys(headers).find(
        (h) => h.toLowerCase() === "x-powered-by"
    );
    if (poweredBy && headers[poweredBy]) {
        suspicious.push(`X-Powered-By disclosure: ${headers[poweredBy]}`);
    }

    // Check for debug mode indicators
    if (
        body.includes("DEBUG = True") ||
        body.includes("debug mode") ||
        body.includes("stack trace")
    ) {
        suspicious.push("Debug mode may be enabled");
    }

    // Check for backup files
    if (body.includes(".bak") || body.includes(".backup") || body.includes(".old")) {
        suspicious.push("Possible backup files referenced");
    }

    return suspicious;
}

export async function analyzeResponse(
    sdk: SDK,
    input: AnalyzeResponseInput
): Promise<AnalyzeResponseOutput> {
    // Validate input
    if (!input.requestId) {
        return {
            success: false,
            error: "requestId is required",
        };
    }

    try {
        sdk.console.log(`[MCP] Analyzing response for request ${input.requestId}`);

        // Get request/response from Caido
        const reqRes = await sdk.requests.get(input.requestId);

        if (!reqRes) {
            return {
                success: false,
                error: `Request ${input.requestId} not found`,
            };
        }

        const { request, response } = reqRes;

        if (!response) {
            return {
                success: false,
                error: "No response found for this request",
            };
        }

        // Extract data
        const statusCode = response.getCode();
        const body = response.getBody()?.toText() || "";
        const headers: Record<string, string> = {};

        for (const header of response.getHeaders()) {
            headers[header.name] = header.value;
        }

        // Get content type
        const contentType =
            Object.keys(headers).find((h) => h.toLowerCase() === "content-type")
                ? headers[
                Object.keys(headers).find((h) => h.toLowerCase() === "content-type")!
                ]
                : "unknown";

        // Analyze
        const securityHeaders = analyzeSecurityHeaders(headers);
        const sensitiveData = analyzeSensitiveData(body);
        const errors = analyzeErrors(body);
        const suspicious = detectSuspicious(statusCode, headers, body);

        // Custom pattern matching
        const customMatches: { pattern: string; matches: string[] }[] = [];
        if (input.patterns) {
            for (const pattern of input.patterns) {
                try {
                    const regex = new RegExp(pattern, "gi");
                    const found = body.match(regex);
                    if (found) {
                        customMatches.push({
                            pattern,
                            matches: found.slice(0, 10), // Limit results
                        });
                    }
                } catch (regexError) {
                    sdk.console.error(`[MCP] Invalid regex pattern: ${pattern}`);
                }
            }
        }

        sdk.console.log(`[MCP] Analysis complete. Found ${suspicious.length} suspicious patterns.`);

        return {
            success: true,
            analysis: {
                statusCode,
                contentType,
                contentLength: body.length,
                suspicious,
                securityHeaders,
                sensitiveData,
                errors,
                customMatches,
            },
        };
    } catch (error) {
        sdk.console.error(`[MCP] Analysis failed: ${error}`);
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}
