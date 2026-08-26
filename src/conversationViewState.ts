/** Shared, transport-free state contract for repository-owned conversation views. */
export interface ConversationViewSettings {
  readonly showCampaignMemory: boolean
  readonly showAttackAtlas: boolean
  readonly showRedteamResults: boolean
  readonly showHunter: boolean
  readonly showWebshellManager: boolean
}

export type ConversationViewField = keyof ConversationViewSettings

export const DEFAULT_CONVERSATION_VIEW_SETTINGS: ConversationViewSettings = Object.freeze({
  showCampaignMemory: true,
  showAttackAtlas: true,
  showRedteamResults: true,
  showHunter: true,
  showWebshellManager: true,
})

export interface ConversationViewSnapshotValue {
  readonly status: 'loading' | 'ready' | 'unavailable'
  readonly value: ConversationViewSettings | undefined
}

/** Unavailable or malformed settings fail open, matching the child view clients. */
export function effectiveConversationViewSettings(
  snapshot: ConversationViewSnapshotValue,
): ConversationViewSettings {
  return snapshot.status === 'ready' && snapshot.value !== undefined
    ? snapshot.value
    : DEFAULT_CONVERSATION_VIEW_SETTINGS
}

/** Scope writes resolve after recovery, so success must be verified from the settled snapshot. */
export function conversationViewWriteApplied(
  snapshot: ConversationViewSnapshotValue,
  field: ConversationViewField,
  expected: boolean,
): boolean {
  return snapshot.status === 'ready' && snapshot.value?.[field] === expected
}
