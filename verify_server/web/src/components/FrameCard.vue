<script setup>
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import {
  decodeBase64,
  formatBytes,
  formatTime,
  frameTitle,
  sessionKey,
  shortHash,
  tagTypeForDirection,
  tagTypeForResult,
} from '../utils/format'

const props = defineProps({
  record: { type: Object, required: true },
})

const payloadText = computed(() => decodeBase64(props.record.payload_b64))
const title = computed(() => frameTitle(props.record))
const auditKey = computed(() => sessionKey(props.record))
const timeText = computed(() => formatTime(props.record.time || props.record.ts))
const sizeText = computed(() => formatBytes(props.record.frame_size))
const hashText = computed(() => shortHash(props.record.record_hash, 12))
const prevHashText = computed(() => shortHash(props.record.prev_hash, 8))
const directionType = computed(() => tagTypeForDirection(props.record.direction))
const resultType = computed(() => tagTypeForResult(props.record.result))
</script>

<template>
  <article class="frame-card">
    <div class="frame-rail" :class="record.direction === 'V->C' ? 'rail-out' : 'rail-in'" />

    <div class="frame-main">
      <header class="frame-head">
        <div class="frame-title">
          <el-tag size="small" effect="dark">{{ title }}</el-tag>
          <strong>#{{ record.id ?? '-' }}</strong>
          <span>{{ record.event_type || '-' }}</span>
        </div>
        <div class="frame-tags">
          <el-tag size="small" :type="directionType">{{ record.direction || 'n/a' }}</el-tag>
          <el-tag size="small" :type="resultType">{{ record.result || 'unknown' }}</el-tag>
        </div>
      </header>

      <dl class="frame-meta">
        <div>
          <dt>时间</dt>
          <dd>{{ timeText }}</dd>
        </div>
        <div>
          <dt>Client</dt>
          <dd>{{ record.client_id || '-' }}</dd>
        </div>
        <div>
          <dt>Session</dt>
          <dd>
            <RouterLink v-if="auditKey" :to="{ name: 'audit-session', query: { id: auditKey } }">
              {{ auditKey }}
            </RouterLink>
            <span v-else>-</span>
          </dd>
        </div>
        <div>
          <dt>PTY</dt>
          <dd>{{ record.pty_session_id || '-' }}</dd>
        </div>
        <div>
          <dt>Seq</dt>
          <dd>{{ record.seq_num || '-' }}</dd>
        </div>
        <div>
          <dt>大小</dt>
          <dd>{{ sizeText }}</dd>
        </div>
      </dl>

      <section v-if="payloadText" class="payload-panel">
        <div class="payload-head">
          <span>Payload</span>
          <span>{{ sizeText }}</span>
        </div>
        <pre>{{ payloadText }}</pre>
      </section>

      <footer class="frame-foot">
        <span v-if="record.error_code" class="error-code">{{ record.error_code }}</span>
        <span>hash {{ hashText }}</span>
        <span v-if="record.prev_hash">prev {{ prevHashText }}</span>
      </footer>
    </div>
  </article>
</template>
