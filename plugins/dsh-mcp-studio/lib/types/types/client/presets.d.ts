/**
 * Built-in one-click server presets: JSON snippets for the MCP servers
 * people most commonly wire up. Each chip fills the paste drawer; importing
 * stages the row(s) as usual.
 */
export interface ServerPreset {
    readonly id: string;
    readonly label: string;
    readonly description: string;
    readonly json: string;
}
export declare const SERVER_PRESETS: readonly ServerPreset[];
