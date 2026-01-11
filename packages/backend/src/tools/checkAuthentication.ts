// =========================================
// MCP Tool: checkAuthentication
// =========================================
// Test authentication bypass vulnerabilities

import type { SDK } from "caido:plugin";
import { RequestSpec } from "caido:plugin";
import { isTargetAllowed } from "../state";

// Delay helper
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface CheckAuthInput {
    url: string;
    authMethod?: "bearer" | "basic" | "cookie" | "custom";
    credentials?: {
        token?: string;
        username?: string;
        password?: string;
        cookie?: string;
        header?: { name: string; value: string };
    };
}

export interface AuthTest {
    name: string;
    description: string;
    statusCode: number;
    passed: boolean; // True if protection is working (request was blocked)
    details: string;
}

export interface CheckAuthOutput {
    success: boolean;
    error?: string;
    vulnerable: boolean;
    tests: AuthTest[];
    vulnerabilities: string[];
}

// Bypass headers to test
const BYPASS_HEADERS = [
    { name: "X-Original-URL", value: "/" },
    { name: "X-Rewrite-URL", value: "/" },
    { name: "X-Forwarded-For", value: "127.0.0.1" },
    { name: "X-Forwarded-Host", value: "localhost" },
    { name: "X-Host", value: "localhost" },
    { name: "X-Custom-IP-Authorization", value: "127.0.0.1" },
    { name: "X-Real-IP", value: "127.0.0.1" },
    { name: "X-Remote-IP", value: "127.0.0.1" },
    { name: "X-Remote-Addr", value: "127.0.0.1" },
    { name: "X-Client-IP", value: "127.0.0.1" },
    { name: "X-Originating-IP", value: "127.0.0.1" },
];

// Methods to test for tampering
const METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];

export async function checkAuthentication(
    sdk: SDK,
    input: CheckAuthInput
): Promise<CheckAuthOutput> {
    const tests: AuthTest[] = [];
    const vulnerabilities: string[] = [];

    // Validate input
    if (!input.url) {
        return {
            success: false,
            error: "URL is required",
            vulnerable: false,
            tests: [],
            vulnerabilities: [],
        };
    }

    // Check if target is allowed
    if (!isTargetAllowed(input.url)) {
        return {
            success: false,
            error: "Target not allowed. Add the domain to allowed targets first.",
            vulnerable: false,
            tests: [],
            vulnerabilities: [],
        };
    }

    sdk.console.log(`[MCP] Starting authentication bypass tests on ${input.url}`);

    try {
        // Test 1: Request without authentication
        sdk.console.log("[MCP] Test 1: Request without authentication");
        {
            const requestSpec = new RequestSpec(input.url);
            requestSpec.setMethod("GET");

            const response = await sdk.requests.send(requestSpec);
            const statusCode = response.response.getCode();

            const passed = statusCode === 401 || statusCode === 403;
            tests.push({
                name: "No Authentication",
                description: "Request without any authentication credentials",
                statusCode,
                passed,
                details: passed
                    ? "Correctly blocked unauthenticated request"
                    : `Unauthenticated request returned ${statusCode} - may be accessible`,
            });

            if (!passed && statusCode === 200) {
                vulnerabilities.push("Resource accessible without authentication");
            }
        }

        await delay(100);

        // Test 2: Request with invalid token/credentials
        sdk.console.log("[MCP] Test 2: Request with invalid credentials");
        {
            const requestSpec = new RequestSpec(input.url);
            requestSpec.setMethod("GET");

            // Add invalid credentials based on auth method
            switch (input.authMethod) {
                case "bearer":
                    requestSpec.setHeader("Authorization", "Bearer invalid_token_12345");
                    break;
                case "basic":
                    requestSpec.setHeader("Authorization", "Basic aW52YWxpZDppbnZhbGlk"); // invalid:invalid
                    break;
                case "cookie":
                    requestSpec.setHeader("Cookie", "session=invalid_session_token");
                    break;
                default:
                    requestSpec.setHeader("Authorization", "Bearer invalid_token_12345");
            }

            const response = await sdk.requests.send(requestSpec);
            const statusCode = response.response.getCode();

            const passed = statusCode === 401 || statusCode === 403;
            tests.push({
                name: "Invalid Credentials",
                description: "Request with invalid authentication credentials",
                statusCode,
                passed,
                details: passed
                    ? "Correctly rejected invalid credentials"
                    : `Invalid credentials returned ${statusCode} - possible bypass`,
            });

            if (!passed && statusCode === 200) {
                vulnerabilities.push("Invalid credentials accepted");
            }
        }

        await delay(100);

        // Test 3: Header manipulation tests
        sdk.console.log("[MCP] Test 3: Header manipulation tests");
        for (const header of BYPASS_HEADERS.slice(0, 5)) {
            // Limit for performance
            const requestSpec = new RequestSpec(input.url);
            requestSpec.setMethod("GET");
            requestSpec.setHeader(header.name, header.value);

            try {
                const response = await sdk.requests.send(requestSpec);
                const statusCode = response.response.getCode();

                if (statusCode === 200) {
                    tests.push({
                        name: `Header Bypass: ${header.name}`,
                        description: `Testing ${header.name}: ${header.value}`,
                        statusCode,
                        passed: false,
                        details: `Header ${header.name} may bypass authentication`,
                    });
                    vulnerabilities.push(`Header bypass possible with ${header.name}`);
                }
            } catch (error) {
                // Ignore failed requests
            }

            await delay(100);
        }

        // Test 4: Method tampering
        sdk.console.log("[MCP] Test 4: HTTP method tampering");
        for (const method of METHODS_TO_TEST.slice(0, 4)) {
            // Limit for performance
            const requestSpec = new RequestSpec(input.url);
            requestSpec.setMethod(method);

            try {
                const response = await sdk.requests.send(requestSpec);
                const statusCode = response.response.getCode();

                // Check if unexpected method returns 200
                if (statusCode === 200 && method !== "GET" && method !== "HEAD") {
                    tests.push({
                        name: `Method Tampering: ${method}`,
                        description: `Testing HTTP method ${method}`,
                        statusCode,
                        passed: false,
                        details: `${method} method may bypass authentication`,
                    });
                    vulnerabilities.push(`Method tampering possible with ${method}`);
                }
            } catch (error) {
                // Ignore failed requests
            }

            await delay(100);
        }

        // Test 5: Path manipulation
        sdk.console.log("[MCP] Test 5: Path manipulation");
        const pathVariations = [
            input.url + "/",
            input.url + "/.",
            input.url + "//",
            input.url + ";",
            input.url + "%2f",
        ];

        for (const path of pathVariations) {
            try {
                const requestSpec = new RequestSpec(path);
                requestSpec.setMethod("GET");

                const response = await sdk.requests.send(requestSpec);
                const statusCode = response.response.getCode();

                if (statusCode === 200) {
                    tests.push({
                        name: "Path Manipulation",
                        description: `Testing path variation: ${path}`,
                        statusCode,
                        passed: false,
                        details: "Path manipulation may bypass authentication",
                    });
                    vulnerabilities.push(`Path manipulation bypass: ${path}`);
                    break; // One finding is enough
                }
            } catch (error) {
                // Ignore failed requests
            }

            await delay(100);
        }

        // Create findings for vulnerabilities
        for (const vuln of vulnerabilities) {
            try {
                const requestSpec = new RequestSpec(input.url);
                const response = await sdk.requests.send(requestSpec);

                await sdk.findings.create({
                    title: "Authentication Bypass Vulnerability",
                    description: vuln,
                    reporter: "MCP Auth Checker",
                    request: response.request,
                    dedupeKey: `mcp-auth-${input.url}-${vuln}`,
                });
            } catch (error) {
                sdk.console.error(`[MCP] Failed to create finding: ${error}`);
            }
        }

        const isVulnerable = vulnerabilities.length > 0;
        sdk.console.log(
            `[MCP] Authentication check complete. Vulnerable: ${isVulnerable}`
        );

        return {
            success: true,
            vulnerable: isVulnerable,
            tests,
            vulnerabilities,
        };
    } catch (error) {
        sdk.console.error(`[MCP] Authentication check failed: ${error}`);
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error),
            vulnerable: false,
            tests,
            vulnerabilities,
        };
    }
}
