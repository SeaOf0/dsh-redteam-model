/** Host plugin: owns the `mcp-studio` settings namespace, mounts one mcp-client per enabled row (hot-swap on edit, dispose on remove), and serves live status aggregated from the tool registry over the plugin's loopback channel. */
import type { Context } from '@deepseek-ai/cordis';
import { type StudioSection } from './types.ts';
export declare const name = "dsh-mcp-studio";
export declare const inject: string[];
/** Settings namespace owned by this plugin (client and Host spell the same value). */
export declare const STUDIO_SETTINGS_NAMESPACE: import("@deepseek-ai/dsh-settings").SettingsNamespace;
export declare function apply(ctx: Context, config: StudioSection): void;
