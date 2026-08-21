/** Shared section shape, schema, and pure helpers. */
import z from '@deepseek-ai/schemastery';
import type { Config as McpClientConfig } from '@deepseek-ai/dsh-mcp-client';
/** Stable row id grammar. */
export declare const ID_PATTERN: RegExp;
/** Default per-tool-call timeout passed to the mcp-client bridge (ms). */
export declare const DEFAULT_TOOL_CALL_TIMEOUT_MS = 60000;
export type Transport = 'stdio' | 'streamable-http';
/** One user-configured MCP server row. */
export interface ServerEntry {
    /** Stable row identity used to diff mounted instances. */
    readonly id: string;
    /** Disabled rows are kept in the document but mount nothing. */
    readonly enabled: boolean;
    /** Model-facing tool namespace: `mcp__<name>__<tool>`; unique across enabled rows. */
    readonly name: string;
    readonly transport: Transport;
    /** stdio: executable to spawn. */
    readonly command: string;
    /** stdio: one-line argument string (split on whitespace, quotes honored). */
    readonly argsLine: string;
    /** stdio: extra environment variables merged over the scrubbed parent env. */
    readonly env: Record<string, string>;
    /** stdio: working directory for the child process. */
    readonly cwd: string;
    /** streamable-http: MCP endpoint URL. */
    readonly url: string;
    /** streamable-http: extra request headers (e.g. Authorization). */
    readonly headers: Record<string, string>;
    /** Per-tool-call timeout in milliseconds. */
    readonly toolCallTimeoutMs: number;
    /** Reject the mount when the initial connection or tool sync fails. */
    readonly failOnStartupError: boolean;
}
/** The whole `mcp-studio` settings section. */
export interface StudioSection {
    readonly servers: ServerEntry[];
}
export declare const ServerEntrySchema: z<ServerEntry>;
export declare const Config: z<StudioSection>;
/** Split one argument line into argv tokens; single/double quotes and backslash escapes are honored. */
export declare function splitArgs(line: string): string[];
/** Project one server row onto the mcp-client config shape. */
export declare function toMcpClientConfig(server: ServerEntry): McpClientConfig;
/** Cross-field constraints the schema cannot express; throwing refuses the write. */
export declare function validateSection(value: StudioSection): void;
