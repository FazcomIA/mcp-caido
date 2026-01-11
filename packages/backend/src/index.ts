// =========================================
// MCP Server Plugin - Backend Entry Point
// =========================================
// Registers all MCP tools as APIs available to the frontend

import type { SDK, DefineAPI, DefineEvents } from "caido:plugin";

// Import tools
import { sendRequest, SendRequestInput, SendRequestOutput } from "./tools/sendRequest";
import { scanForVulnerabilities, ScanInput, ScanOutput } from "./tools/scanForVulnerabilities";
import { analyzeResponse, AnalyzeResponseInput, AnalyzeResponseOutput } from "./tools/analyzeResponse";
import { fuzzParameter, FuzzParameterInput, FuzzParameterOutput } from "./tools/fuzzParameter";
import {
    interceptRequest,
    stopIntercept,
    getIntercepted,
    listInterceptPatterns,
    initInterceptHandler,
    InterceptRequestInput,
    InterceptRequestOutput,
    StopInterceptInput,
    GetInterceptedInput,
    GetInterceptedOutput,
    ListInterceptPatternsOutput,
} from "./tools/interceptRequest";
import { checkAuthentication, CheckAuthInput, CheckAuthOutput } from "./tools/checkAuthentication";
import { exportFindings, ExportFindingsInput, ExportFindingsOutput } from "./tools/exportFindings";
import { replayRequest, ReplayRequestInput, ReplayRequestOutput } from "./tools/replayRequest";
import { getRequestHistory, GetRequestHistoryInput, GetRequestHistoryOutput } from "./tools/getRequestHistory";
import { getFindings, GetFindingsInput, GetFindingsOutput } from "./tools/getFindings";

// Import state management
import {
    setAllowedTargets as setTargets,
    getAllowedTargets,
    getStatus as getPluginStatus,
    PluginStatus,
} from "./state";

// =========================================
// Helper Functions for State Management
// =========================================

function setAllowedTargets(sdk: SDK, targets: string[]): { success: boolean; allowedTargets: string[] } {
    const result = setTargets(targets);
    sdk.console.log(`[MCP] Set allowed targets: ${result.join(", ")}`);
    return {
        success: true,
        allowedTargets: result,
    };
}

function getStatus(sdk: SDK): { success: boolean } & PluginStatus {
    const status = getPluginStatus();
    return {
        success: true,
        ...status,
    };
}

// =========================================
// API Definition
// =========================================

export type API = DefineAPI<{
    // Core MCP Tools
    sendRequest: typeof sendRequest;
    scanForVulnerabilities: typeof scanForVulnerabilities;
    analyzeResponse: typeof analyzeResponse;
    fuzzParameter: typeof fuzzParameter;
    interceptRequest: typeof interceptRequest;
    stopIntercept: typeof stopIntercept;
    getIntercepted: typeof getIntercepted;
    listInterceptPatterns: typeof listInterceptPatterns;
    checkAuthentication: typeof checkAuthentication;
    exportFindings: typeof exportFindings;
    replayRequest: typeof replayRequest;
    getRequestHistory: typeof getRequestHistory;
    getFindings: typeof getFindings;

    // State Management
    setAllowedTargets: typeof setAllowedTargets;
    getStatus: typeof getStatus;
}>;

export type Events = DefineEvents<{}>;

// =========================================
// Plugin Initialization
// =========================================

export function init(sdk: SDK<API, Events>): void {
    sdk.console.log("[MCP] Initializing MCP Server Plugin...");

    // Register all APIs
    sdk.api.register("sendRequest", sendRequest);
    sdk.api.register("scanForVulnerabilities", scanForVulnerabilities);
    sdk.api.register("analyzeResponse", analyzeResponse);
    sdk.api.register("fuzzParameter", fuzzParameter);
    sdk.api.register("interceptRequest", interceptRequest);
    sdk.api.register("stopIntercept", stopIntercept);
    sdk.api.register("getIntercepted", getIntercepted);
    sdk.api.register("listInterceptPatterns", listInterceptPatterns);
    sdk.api.register("checkAuthentication", checkAuthentication);
    sdk.api.register("exportFindings", exportFindings);
    sdk.api.register("replayRequest", replayRequest);
    sdk.api.register("getRequestHistory", getRequestHistory);
    sdk.api.register("getFindings", getFindings);

    // State management APIs
    sdk.api.register("setAllowedTargets", setAllowedTargets);
    sdk.api.register("getStatus", getStatus);

    // Initialize intercept handler
    initInterceptHandler(sdk);

    sdk.console.log("[MCP] MCP Server Plugin initialized successfully!");
    sdk.console.log("[MCP] Available tools: 15");
    sdk.console.log("[MCP] - sendRequest: Send custom HTTP requests");
    sdk.console.log("[MCP] - scanForVulnerabilities: Automated vulnerability scanner");
    sdk.console.log("[MCP] - analyzeResponse: Analyze HTTP responses");
    sdk.console.log("[MCP] - fuzzParameter: Fuzz parameters with payloads");
    sdk.console.log("[MCP] - interceptRequest: Intercept and monitor requests");
    sdk.console.log("[MCP] - checkAuthentication: Test authentication bypass");
    sdk.console.log("[MCP] - exportFindings: Export vulnerabilities");
    sdk.console.log("[MCP] - replayRequest: Replay requests with modifications");
    sdk.console.log("[MCP] - getRequestHistory: Get request history");
    sdk.console.log("[MCP] - getFindings: Get findings");
    sdk.console.log("[MCP] - setAllowedTargets: Configure allowed targets");
    sdk.console.log("[MCP] - getStatus: Get plugin status");
}
