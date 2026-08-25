import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CONVERSATION_VIEW_SETTINGS_NAMESPACE,
  ConversationViewSettingsSchema,
  DEFAULT_CONVERSATION_VIEW_SETTINGS,
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
