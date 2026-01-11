// =========================================
// MCP Tool: scanForVulnerabilities
// =========================================
// Automated vulnerability scanner for XSS, SQLi, Command Injection, Path Traversal

import type { SDK } from "caido:plugin";
import { RequestSpec } from "caido:plugin";
import { isTargetAllowed, createScan, updateScanProgress, completeScan } from "../state";
import {
    XSS_PAYLOADS,
    SQLI_PAYLOADS,
    COMMAND_INJECTION_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    VULNERABILITY_PATTERNS,
} from "../utils/payloads";

export type ScanType = "xss" | "sqli" | "command_injection" | "path_traversal";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface ScanInput {
    url: string;
    scanTypes?: ScanType[];
    depth?: number;
    maxRequests?: number;
}

export interface Finding {
    id: string;
    type: ScanType;
    severity: Severity;
    title: string;
    description: string;
    url: string;
    payload: string;
    evidence: string;
    request?: string;
    response?: string;
}

export interface ScanOutput {
    success: boolean;
    error?: string;
    scanId?: string;
    findings: Finding[];
    summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
}

// Delay helper
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// Generate unique ID
const generateId = () => Math.random().toString(36).substring(2, 15);

// Get payloads for scan type
function getPayloadsForType(type: ScanType): string[] {
    switch (type) {
        case "xss":
            return XSS_PAYLOADS.slice(0, 10); // Limit for performance
        case "sqli":
            return SQLI_PAYLOADS.slice(0, 10);
        case "command_injection":
            return COMMAND_INJECTION_PAYLOADS.slice(0, 10);
        case "path_traversal":
            return PATH_TRAVERSAL_PAYLOADS.slice(0, 10);
        default:
            return [];
    }
}

// Get severity for vulnerability type
function getSeverityForType(type: ScanType): Severity {
    switch (type) {
        case "sqli":
            return "CRITICAL";
        case "command_injection":
            return "CRITICAL";
        case "xss":
            return "HIGH";
        case "path_traversal":
            return "HIGH";
        default:
            return "MEDIUM";
    }
}

// Check if response indicates vulnerability
function detectVulnerability(
    type: ScanType,
    payload: string,
    responseBody: string
): { detected: boolean; evidence: string } {
    const patterns = VULNERABILITY_PATTERNS[type];

    if (!patterns) {
        // Check if payload is reflected
        if (responseBody.includes(payload)) {
            return {
                detected: true,
                evidence: `Payload reflected in response: "${payload.substring(0, 50)}..."`,
            };
        }
        return { detected: false, evidence: "" };
    }

    // Check patterns based on type
    if (type === "xss" && patterns.reflected) {
        for (const pattern of patterns.reflected) {
            if (pattern.test(responseBody)) {
                return {
                    detected: true,
                    evidence: `XSS pattern detected: ${pattern.toString()}`,
                };
            }
        }
        // Also check for direct reflection
        if (responseBody.includes(payload)) {
            return {
                detected: true,
                evidence: `Payload reflected in response`,
            };
        }
    }

    if (type === "sqli" && patterns.error) {
        for (const pattern of patterns.error) {
            const match = responseBody.match(pattern);
            if (match) {
                return {
                    detected: true,
                    evidence: `SQL error detected: "${match[0].substring(0, 100)}"`,
                };
            }
        }
    }

    if (type === "command_injection") {
        if (patterns.unix) {
            for (const pattern of patterns.unix) {
                const match = responseBody.match(pattern);
                if (match) {
                    return {
                        detected: true,
                        evidence: `Command execution detected: "${match[0].substring(0, 100)}"`,
                    };
                }
            }
        }
        if (patterns.windows) {
            for (const pattern of patterns.windows) {
                const match = responseBody.match(pattern);
                if (match) {
                    return {
                        detected: true,
                        evidence: `Command execution detected: "${match[0].substring(0, 100)}"`,
                    };
                }
            }
        }
    }

    if (type === "path_traversal") {
        if (patterns.unix) {
            for (const pattern of patterns.unix) {
                const match = responseBody.match(pattern);
                if (match) {
                    return {
                        detected: true,
                        evidence: `Path traversal detected: "${match[0].substring(0, 100)}"`,
                    };
                }
            }
        }
        if (patterns.windows) {
            for (const pattern of patterns.windows) {
                const match = responseBody.match(pattern);
                if (match) {
                    return {
                        detected: true,
                        evidence: `Path traversal detected: "${match[0].substring(0, 100)}"`,
                    };
                }
            }
        }
    }

    return { detected: false, evidence: "" };
}

// Inject payload into URL
function injectPayloadInUrl(url: string, payload: string): string[] {
    const injectedUrls: string[] = [];

    try {
        const parsed = new URL(url);

        // Inject in query parameters
        for (const [key, value] of parsed.searchParams) {
            const newUrl = new URL(url);
            newUrl.searchParams.set(key, payload);
            injectedUrls.push(newUrl.toString());
        }

        // If no params, add as a new param
        if (parsed.searchParams.size === 0) {
            const newUrl = new URL(url);
            newUrl.searchParams.set("test", payload);
            injectedUrls.push(newUrl.toString());
        }

        // For path traversal, inject in path
        if (injectedUrls.length === 0) {
            injectedUrls.push(`${url}/${payload}`);
        }
    } catch {
        injectedUrls.push(`${url}?test=${encodeURIComponent(payload)}`);
    }

    return injectedUrls;
}

export async function scanForVulnerabilities(
    sdk: SDK,
    input: ScanInput
): Promise<ScanOutput> {
    const scanId = generateId();
    const findings: Finding[] = [];
    let requestCount = 0;

    // Validate input
    if (!input.url) {
        return {
            success: false,
            error: "URL is required",
            findings: [],
            summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        };
    }

    // Check if target is allowed
    if (!isTargetAllowed(input.url)) {
        return {
            success: false,
            error: "Target not allowed. Add the domain to allowed targets first.",
            findings: [],
            summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        };
    }

    const scanTypes = input.scanTypes || ["xss", "sqli", "command_injection", "path_traversal"];
    const maxRequests = input.maxRequests || 50;

    sdk.console.log(`[MCP] Starting vulnerability scan on ${input.url}`);
    sdk.console.log(`[MCP] Scan types: ${scanTypes.join(", ")}`);
    sdk.console.log(`[MCP] Max requests: ${maxRequests}`);

    // Create scan in state
    createScan(scanId, input.url, scanTypes);

    try {
        // Iterate through each scan type
        for (const scanType of scanTypes) {
            if (requestCount >= maxRequests) {
                sdk.console.log(`[MCP] Max requests reached, stopping scan`);
                break;
            }

            const payloads = getPayloadsForType(scanType);
            sdk.console.log(`[MCP] Testing ${scanType} with ${payloads.length} payloads`);

            for (const payload of payloads) {
                if (requestCount >= maxRequests) break;

                const injectedUrls = injectPayloadInUrl(input.url, payload);

                for (const testUrl of injectedUrls) {
                    if (requestCount >= maxRequests) break;

                    try {
                        // Create request
                        const requestSpec = new RequestSpec(testUrl);
                        requestSpec.setMethod("GET");

                        // Send request
                        const reqResponse = await sdk.requests.send(requestSpec);
                        requestCount++;

                        // Update progress
                        updateScanProgress(scanId, Math.floor((requestCount / maxRequests) * 100));

                        // Analyze response
                        const responseBody = reqResponse.response.getBody()?.toText() || "";
                        const detection = detectVulnerability(scanType, payload, responseBody);

                        if (detection.detected) {
                            const finding: Finding = {
                                id: generateId(),
                                type: scanType,
                                severity: getSeverityForType(scanType),
                                title: `${scanType.toUpperCase()} Vulnerability Detected`,
                                description: `A ${scanType} vulnerability was detected at ${testUrl}`,
                                url: testUrl,
                                payload,
                                evidence: detection.evidence,
                            };

                            findings.push(finding);
                            sdk.console.log(`[MCP] FOUND: ${finding.title} at ${testUrl}`);

                            // Create finding in Caido
                            try {
                                await sdk.findings.create({
                                    title: finding.title,
                                    description: `${finding.description}\n\nPayload: ${payload}\n\nEvidence: ${detection.evidence}`,
                                    reporter: "MCP Scanner",
                                    request: reqResponse.request,
                                    dedupeKey: `mcp-${scanType}-${testUrl}-${payload}`,
                                });
                            } catch (findingError) {
                                sdk.console.error(`[MCP] Failed to create finding: ${findingError}`);
                            }
                        }

                        // Rate limiting
                        await delay(100);
                    } catch (reqError) {
                        sdk.console.error(`[MCP] Request failed: ${reqError}`);
                    }
                }
            }
        }

        // Complete scan
        completeScan(scanId, "completed");

        // Calculate summary
        const summary = {
            total: findings.length,
            critical: findings.filter((f) => f.severity === "CRITICAL").length,
            high: findings.filter((f) => f.severity === "HIGH").length,
            medium: findings.filter((f) => f.severity === "MEDIUM").length,
            low: findings.filter((f) => f.severity === "LOW").length,
            info: findings.filter((f) => f.severity === "INFO").length,
        };

        sdk.console.log(`[MCP] Scan completed. Found ${summary.total} vulnerabilities.`);

        return {
            success: true,
            scanId,
            findings,
            summary,
        };
    } catch (error) {
        completeScan(scanId, "failed");
        sdk.console.error(`[MCP] Scan failed: ${error}`);
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
            scanId,
            findings,
            summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        };
    }
}
