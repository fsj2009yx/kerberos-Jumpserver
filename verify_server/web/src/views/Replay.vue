<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Refresh, Search } from '@element-plus/icons-vue'
import { fetchReplay, fetchTargets } from '../api/verify'
import FrameCard from '../components/FrameCard.vue'
import { decodeBase64 } from '../utils/format'

const route = useRoute()
const loading = ref(false)
const clientId = ref(String(route.query.client_id || localStorage.getItem('v-webui-audit-client') || ''))
const targetId = ref(String(route.query.target_id || localStorage.getItem('v-webui-audit-target') || ''))
const limit = ref(300)
const frames = ref([])
const targets = ref([])

function renderTerminalText(raw) {
  const text = String(raw || '')
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, '')
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\x1b[()][A-Za-z0-9]/g, '')

  const lines = ['']
  let row = 0
  let col = 0
  for (const char of text) {
    if (char === '\r') {
      col = 0
      continue
    }
    if (char === '\n') {
      row += 1
      col = 0
      if (lines[row] === undefined) lines[row] = ''
      continue
    }
    if (char === '\b') {
      col = Math.max(0, col - 1)
      continue
    }
    if (char < ' ' && char !== '\t') {
      continue
    }
    const line = lines[row] || ''
    const padded = line.length < col ? line.padEnd(col, ' ') : line
    lines[row] = `${padded.slice(0, col)}${char}${padded.slice(col + 1)}`
    col += 1
  }
  return lines.join('\n').replace(/\n{4,}/g, '\n\n\n').trimEnd()
}

const outputFrames = computed(() => {
  return frames.value.filter((item) => item.direction === 'V->C' && item.frame_type === 'output')
})

const transcript = computed(() => {
  const raw = outputFrames.value
    .map((item) => decodeBase64(item.payload_b64))
    .filter(Boolean)
    .join('')
  return renderTerminalText(raw)
})

async function load() {
  const client = clientId.value.trim()
  const target = targetId.value.trim()
  if (!client || !target) {
    ElMessage.warning('请输入 Client 并选择 SSH 节点')
    return
  }
  localStorage.setItem('v-webui-audit-client', client)
  localStorage.setItem('v-webui-audit-target', target)
  loading.value = true
  try {
    const data = await fetchReplay(client, target, limit.value)
    frames.value = data?.frames || []
  } catch (error) {
    ElMessage.error(error.message || String(error))
  } finally {
    loading.value = false
  }
}

async function loadTargets() {
  try {
    const data = await fetchTargets()
    targets.value = data.targets || []
  } catch (error) {
    ElMessage.error(error.message || String(error))
  }
}

watch(
  () => [route.query.client_id, route.query.target_id],
  ([client, target]) => {
    if (client && client !== clientId.value) {
      clientId.value = String(client)
    }
    if (target && target !== targetId.value) {
      targetId.value = String(target)
    }
    if (clientId.value && targetId.value) load()
  },
)

onMounted(() => {
  loadTargets()
  if (clientId.value && targetId.value) {
    load()
  }
})
</script>

<template>
  <div class="page-stack">
    <section class="toolbar-row">
      <div>
        <h2>输出回放</h2>
        <p>按 Client 和 SSH 节点回放终端输出，输入记录保留在下方 Frame 中</p>
      </div>
      <el-button type="primary" :icon="Refresh" :loading="loading" @click="load">回放</el-button>
    </section>

    <section class="filter-bar">
      <el-input v-model="clientId" clearable placeholder="CLIENT_1" :prefix-icon="Search" />
      <el-select v-model="targetId" clearable filterable placeholder="SSH 节点">
        <el-option v-for="target in targets" :key="target.id" :label="target.id" :value="target.id" />
      </el-select>
      <el-input-number v-model="limit" :min="10" :max="1000" :step="10" controls-position="right" />
    </section>

    <section class="terminal-panel">
      <div class="terminal-head">
        <span>{{ outputFrames.length }} output frames / {{ frames.length }} total</span>
        <span>{{ transcript.length }} chars</span>
      </div>
      <pre>{{ transcript || '暂无输出' }}</pre>
    </section>

    <section v-loading="loading" class="frame-list">
      <FrameCard v-for="record in frames" :key="record.id" :record="record" />
      <el-empty v-if="frames.length === 0 && !loading" description="暂无可回放 frame" />
    </section>
  </div>
</template>
