<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Refresh, Search } from '@element-plus/icons-vue'
import { fetchAuditFrames, fetchTargets } from '../api/verify'
import FrameCard from '../components/FrameCard.vue'

const route = useRoute()
const loading = ref(false)
const clientId = ref(String(route.query.client_id || localStorage.getItem('v-webui-audit-client') || ''))
const targetId = ref(String(route.query.target_id || localStorage.getItem('v-webui-audit-target') || ''))
const limit = ref(200)
const records = ref([])
const targets = ref([])

const stats = computed(() => {
  const input = records.value.filter((item) => item.direction === 'C->V').length
  const output = records.value.filter((item) => item.direction === 'V->C').length
  const failed = records.value.filter((item) => item.result === 'fail').length
  return { input, output, failed }
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
    const data = await fetchAuditFrames(client, target, limit.value)
    records.value = data?.records || []
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
        <h2>会话审计</h2>
        <p>按 Client 和 SSH 节点聚合 PTY Frame</p>
      </div>
      <el-button type="primary" :icon="Refresh" :loading="loading" @click="load">查询</el-button>
    </section>

    <section class="filter-bar">
      <el-input v-model="clientId" clearable placeholder="CLIENT_1" :prefix-icon="Search" />
      <el-select v-model="targetId" clearable filterable placeholder="SSH 节点">
        <el-option v-for="target in targets" :key="target.id" :label="target.id" :value="target.id" />
      </el-select>
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
