<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Refresh, Search } from '@element-plus/icons-vue'
import { fetchReplay } from '../api/verify'
import FrameCard from '../components/FrameCard.vue'
import { decodeBase64 } from '../utils/format'

const route = useRoute()
const loading = ref(false)
const sessionId = ref(String(route.query.id || localStorage.getItem('v-webui-audit-id') || ''))
const limit = ref(300)
const frames = ref([])

const transcript = computed(() => {
  return frames.value
    .map((item) => decodeBase64(item.payload_b64))
    .filter(Boolean)
    .join('')
})

async function load() {
  const id = sessionId.value.trim()
  if (!id) {
    ElMessage.warning('请输入 Session、Client 或 PTY ID')
    return
  }
  localStorage.setItem('v-webui-audit-id', id)
  loading.value = true
  try {
    const data = await fetchReplay(id, limit.value)
    frames.value = data?.frames || []
  } catch (error) {
    ElMessage.error(error.message || String(error))
  } finally {
    loading.value = false
  }
}

watch(
  () => route.query.id,
  (id) => {
    if (id && id !== sessionId.value) {
      sessionId.value = String(id)
      load()
    }
  },
)

onMounted(() => {
  if (sessionId.value) {
    load()
  }
})
</script>

<template>
  <div class="page-stack">
    <section class="toolbar-row">
      <div>
        <h2>输出回放</h2>
        <p>按时间顺序拼接 V->C output frame</p>
      </div>
      <el-button type="primary" :icon="Refresh" :loading="loading" @click="load">回放</el-button>
    </section>

    <section class="filter-bar">
      <el-input v-model="sessionId" clearable placeholder="CLIENT_1:7 / CLIENT_1 / 7" :prefix-icon="Search" />
      <el-input-number v-model="limit" :min="10" :max="1000" :step="10" controls-position="right" />
    </section>

    <section class="terminal-panel">
      <div class="terminal-head">
        <span>{{ frames.length }} frames</span>
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
