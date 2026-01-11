// =========================================
// MCP Server Plugin - Backend State
// =========================================
// Global state for managing allowed targets, active scans, and intercepted requests

import type { Request } from "caido:plugin";

// Allowed targets whitelist
let allowedTargets: string[] = [];

// Active scans tracking
interface ActiveScan {
    id: string;
    url: string;
    scanTypes: string[];
    startTime: number;
    status: "running" | "completed" | "failed";
    progress: number;
}
const activeScans: Map<string, ActiveScan> = new Map();

// Intercepted requests storage (max 100)
interface InterceptedRequest {
    id: string;
    timestamp: number;
    host: string;
    path: string;
    method: string;
    matched: boolean;
}
const interceptedRequests: InterceptedRequest[] = [];
const MAX_INTERCEPTED = 100;

// Intercept patterns
interface InterceptPattern {
    id: string;
    pattern: string;
    regex: RegExp;
    modifications: {
        headers?: Record<string, string>;
        body?: string;
        method?: string;
    };
    enabled: boolean;
}
const interceptPatterns: Map<string, InterceptPattern> = new Map();

// =========================================
// Target Management
// =========================================

export function setAllowedTargets(targets: string[]): string[] {
    allowedTargets = targets.map((t) => t.toLowerCase().trim());
    return allowedTargets;
}

export function getAllowedTargets(): string[] {
    return [...allowedTargets];
}

export function isTargetAllowed(url: string): boolean {
    if (allowedTargets.length === 0) {
        return true; // No restrictions if no targets configured
    }

    try {
        const parsed = new URL(url);
        const host = parsed.hostname.toLowerCase();
        return allowedTargets.some(
            (target) => host === target || host.endsWith(`.${target}`)
        );
    } catch {
        return false;
    }
}

// =========================================
// Scan Management
// =========================================

export function createScan(
    id: string,
    url: string,
    scanTypes: string[]
): ActiveScan {
    const scan: ActiveScan = {
        id,
        url,
        scanTypes,
        startTime: Date.now(),
        status: "running",
        progress: 0,
    };
    activeScans.set(id, scan);
    return scan;
}

export function updateScanProgress(id: string, progress: number): void {
    const scan = activeScans.get(id);
    if (scan) {
        scan.progress = progress;
    }
}

export function completeScan(
    id: string,
    status: "completed" | "failed"
): void {
    const scan = activeScans.get(id);
    if (scan) {
        scan.status = status;
        scan.progress = 100;
    }
}

export function getActiveScans(): ActiveScan[] {
    return Array.from(activeScans.values()).filter((s) => s.status === "running");
}

export function getScan(id: string): ActiveScan | undefined {
    return activeScans.get(id);
}

// =========================================
// Intercept Management
// =========================================

export function addInterceptPattern(
    id: string,
    pattern: string,
    modifications: InterceptPattern["modifications"],
    enabled: boolean = true
): InterceptPattern {
    const interceptPattern: InterceptPattern = {
        id,
        pattern,
        regex: new RegExp(pattern, "i"),
        modifications,
        enabled,
    };
    interceptPatterns.set(id, interceptPattern);
    return interceptPattern;
}

export function removeInterceptPattern(id: string): boolean {
    return interceptPatterns.delete(id);
}

export function getInterceptPatterns(): InterceptPattern[] {
    return Array.from(interceptPatterns.values());
}

export function addInterceptedRequest(
    request: InterceptedRequest
): void {
    interceptedRequests.unshift(request);
    if (interceptedRequests.length > MAX_INTERCEPTED) {
        interceptedRequests.pop();
    }
}

export function getInterceptedRequests(): InterceptedRequest[] {
    return [...interceptedRequests];
}

export function getInterceptedCount(): number {
    return interceptedRequests.length;
}

// =========================================
// Status
// =========================================

export interface PluginStatus {
    activeScans: number;
    interceptedRequests: number;
    allowedTargets: string[];
    interceptPatterns: number;
}

export function getStatus(): PluginStatus {
    return {
        activeScans: getActiveScans().length,
        interceptedRequests: interceptedRequests.length,
        allowedTargets: [...allowedTargets],
        interceptPatterns: interceptPatterns.size,
    };
}
