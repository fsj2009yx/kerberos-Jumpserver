<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh, Search } from '@element-plus/icons-vue'
import { fetchPtyLog } from '../api/verify'
import FrameCard from '../components/FrameCard.vue'
import { decodeBase64 } from '../utils/format'

const loading = ref(false)
const logs = ref([])
const limit = ref(100)
const keyword = ref('')
const direction = ref('')
const result = ref('')
const frameType = ref('')

const frameTypes = computed(() => {
  const values = new Set(logs.value.map((item) => item.frame_type).filter(Boolean))
  return Array.from(values).sort()
})

const filteredLogs = computed(() => {
  const text = keyword.value.trim().toLowerCase()
  return logs.value.filter((item) => {
    if (direction.value && item.direction !== direction.value) {
      return false
    }
    if (result.value && item.result !== result.value) {
      return false
    }
    if (frameType.value && item.frame_type !== frameType.value) {
      return false
    }
    if (!text) {
      return true
    }
    const payload = decodeBase64(item.payload_b64)
    return [
      item.client_id,
      item.client_ip,
      item.session_id,
      item.pty_session_id,
      item.event_type,
      item.frame_type,
      item.error_code,
      payload,
    ]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(text))
  })
})

async function load() {
  loading.value = true
  try {
    const data = await fetchPtyLog(limit.value)
    logs.value = data?.logs || []
  } catch (error) {
    ElMessage.error(error.message || String(error))
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="page-stack">
    <section class="toolbar-row">
      <div>
        <h2>PTY Frames</h2>
        <p>输入、输出、窗口调整和关闭事件的完整审计流</p>
      </div>
      <el-button type="primary" :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
    </section>

    <section class="filter-bar">
      <el-input v-model="keyword" clearable placeholder="搜索 Client / Session / Payload" :prefix-icon="Search" />
      <el-select v-model="direction" clearable placeholder="方向">
        <el-option label="C->V" value="C->V" />
        <el-option label="V->C" value="V->C" />
      </el-select>
      <el-select v-model="result" clearable placeholder="结果">
        <el-option label="ok" value="ok" />
        <el-option label="fail" value="fail" />
      </el-select>
      <el-select v-model="frameType" clearable placeholder="类型">
        <el-option v-for="item in frameTypes" :key="item" :label="item" :value="item" />
      </el-select>
      <el-input-number v-model="limit" :min="10" :max="1000" :step="10" controls-position="right" />
    </section>

    <section class="list-summary">
      <span>显示 {{ filteredLogs.length }} / {{ logs.length }}</span>
      <span>limit {{ limit }}</span>
    </section>

    <section v-loading="loading" class="frame-list">
      <FrameCard v-for="record in filteredLogs" :key="record.id" :record="record" />
      <el-empty v-if="filteredLogs.length === 0 && !loading" description="暂无匹配 frame" />
    </section>
  </div>
</template>
