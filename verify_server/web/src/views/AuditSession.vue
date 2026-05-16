<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Refresh, Search } from '@element-plus/icons-vue'
import { fetchAuditSession } from '../api/verify'
import FrameCard from '../components/FrameCard.vue'

const route = useRoute()
const loading = ref(false)
const sessionId = ref(String(route.query.id || localStorage.getItem('v-webui-audit-id') || ''))
const limit = ref(200)
const records = ref([])

const stats = computed(() => {
  const input = records.value.filter((item) => item.direction === 'C->V').length
  const output = records.value.filter((item) => item.direction === 'V->C').length
  const failed = records.value.filter((item) => item.result === 'fail').length
  return { input, output, failed }
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
    const data = await fetchAuditSession(id, limit.value)
    records.value = data?.records || []
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
        <h2>会话审计</h2>
        <p>按 Session、Client 或 PTY ID 聚合审计记录</p>
      </div>
      <el-button type="primary" :icon="Refresh" :loading="loading" @click="load">查询</el-button>
    </section>

    <section class="filter-bar">
      <el-input v-model="sessionId" clearable placeholder="CLIENT_1:7 / CLIENT_1 / 7" :prefix-icon="Search" />
      <el-input-number v-model="limit" :min="10" :max="1000" :step="10" controls-position="right" />
    </section>

    <section class="metrics-grid narrow">
      <div class="metric-tile tone-green">
        <span class="metric-label">输入</span>
        <strong>{{ stats.input }}</strong>
      </div>
      <div class="metric-tile tone-amber">
        <span class="metric-label">输出</span>
        <strong>{{ stats.output }}</strong>
      </div>
      <div class="metric-tile tone-rose">
        <span class="metric-label">失败</span>
        <strong>{{ stats.failed }}</strong>
      </div>
      <div class="metric-tile tone-blue">
        <span class="metric-label">总记录</span>
        <strong>{{ records.length }}</strong>
      </div>
    </section>

    <section v-loading="loading" class="frame-list">
      <FrameCard v-for="record in records" :key="record.id" :record="record" />
      <el-empty v-if="records.length === 0 && !loading" description="暂无审计记录" />
    </section>
  </div>
</template>
