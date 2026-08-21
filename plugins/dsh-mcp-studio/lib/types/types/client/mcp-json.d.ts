/** MCP config JSON parser and exporter: accepts {"mcpServers":…} / {"servers":…} / bare maps / single-server objects / one wrapper level; non-server metadata keys are ignored. */
import type { ServerDraft } from './contracts.js';
export interface McpJsonParseResult {
    readonly servers: ServerDraft[];
    readonly warnings: string[];
}
/** args array → one argsLine the user can keep editing (quotes preserved). */
export declare function argsToLine(args: readonly unknown[]): string;
/** Built-in starter template pre-filled into the paste drawer. */
export declare const MCP_JSON_TEMPLATE = "{\n  \"mcpServers\": {\n    \"example\": {\n      \"command\": \"npx\",\n      \"args\": [\"-y\", \"@modelcontextprotocol/server-everything\"],\n      \"env\": {}\n    }\n  }\n}";
/**
 * Pretty-print any pasted config (two-space indent); returns an error for invalid JSON.
 */
export declare function formatMcpJson(text: string): {
    text: string;
} | {
    error: string;
};
/** argsLine → argv array (whitespace split, quotes honored). */
export declare function lineToArgs(line: string): string[];
/** Project drafts back onto the Claude Desktop `mcpServers` JSON shape (export path). */
export declare function serversToMcpJson(servers: ReadonlyArray<{
    name: string;
    transport: 'stdio' | 'streamable-http';
    command: string;
    argsLine: string;
    env: ReadonlyArray<{
        key: string;
        value: string;
    }>;
    cwd: string;
    url: string;
    headers: ReadonlyArray<{
        key: string;
        value: string;
    }>;
}>): string;
/** Parse a pasted JSON document into server drafts; names deduplicate with suffixes. */
export declare function parseMcpJson(text: string, existing?: Readonly<Iterable<string>>): McpJsonParseResult | {
    error: string;
};
