import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CONVERSATION_VIEW_SETTINGS_NAMESPACE,
  conversationViewWriteApplied,
  ConversationViewSettingsSchema,
  DEFAULT_CONVERSATION_VIEW_SETTINGS,
  effectiveConversationViewSettings,
  registerConversationViewSettings,
} from '../lib/index.js'

test('conversation view settings default every owned view to visible', () => {
  assert.equal(CONVERSATION_VIEW_SETTINGS_NAMESPACE, 'redteam-manager-ui')
  assert.deepEqual(ConversationViewSettingsSchema({}), DEFAULT_CONVERSATION_VIEW_SETTINGS)
  assert.deepEqual(DEFAULT_CONVERSATION_VIEW_SETTINGS, {
    showCampaignMemory: true,
    showAttackAtlas: true,
    showRedteamResults: true,
    showHunter: true,
    showWebshellManager: true,
  })
})

test('conversation view settings accept booleans and reject malformed values', () => {
  assert.deepEqual(ConversationViewSettingsSchema({ showHunter: false }), {
    ...DEFAULT_CONVERSATION_VIEW_SETTINGS,
    showHunter: false,
  })
  assert.throws(() => ConversationViewSettingsSchema({ showHunter: 'false' }), TypeError)
})

test('conversation view settings fail open instead of displaying a retained unavailable value', () => {
  const hidden = { ...DEFAULT_CONVERSATION_VIEW_SETTINGS, showAttackAtlas: false }
  assert.equal(effectiveConversationViewSettings({ status: 'ready', value: hidden }).showAttackAtlas, false)
  assert.equal(effectiveConversationViewSettings({ status: 'unavailable', value: hidden }).showAttackAtlas, true)
  assert.equal(effectiveConversationViewSettings({ status: 'loading', value: undefined }).showAttackAtlas, true)
})

test('conversation view writes are acknowledged from the settled scope snapshot', () => {
  const visible = { ...DEFAULT_CONVERSATION_VIEW_SETTINGS, showAttackAtlas: true }
  const hidden = { ...DEFAULT_CONVERSATION_VIEW_SETTINGS, showAttackAtlas: false }
  assert.equal(conversationViewWriteApplied({ status: 'ready', value: hidden }, 'showAttackAtlas', false), true)
  assert.equal(conversationViewWriteApplied({ status: 'ready', value: visible }, 'showAttackAtlas', false), false)
  assert.equal(conversationViewWriteApplied({ status: 'unavailable', value: hidden }, 'showAttackAtlas', false), false)
})

test('conversation view settings register once as live settings', () => {
  const injections = []
  const registrations = []
  const ctx = {
    inject(services, callback) {
      injections.push([...services])
      callback({
        settings: {
          register(namespace, schema, options) {
            registrations.push({ namespace, schema, options })
          },
        },
      })
    },
  }

  registerConversationViewSettings(ctx)

  assert.deepEqual(injections, [['settings']])
  assert.equal(registrations.length, 1)
  assert.equal(registrations[0].namespace, CONVERSATION_VIEW_SETTINGS_NAMESPACE)
  assert.equal(registrations[0].schema, ConversationViewSettingsSchema)
  assert.deepEqual(registrations[0].options, { applies: 'live' })
})
