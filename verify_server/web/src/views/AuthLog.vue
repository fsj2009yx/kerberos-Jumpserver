<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh, Search } from '@element-plus/icons-vue'
import { fetchAuthLog } from '../api/verify'
import { formatTime, tagTypeForResult } from '../utils/format'

const loading = ref(false)
const logs = ref([])
const limit = ref(100)
const keyword = ref('')

const filteredLogs = computed(() => {
  const text = keyword.value.trim().toLowerCase()
  if (!text) {
    return logs.value
  }
  return logs.value.filter((item) =>
    [item.client_id, item.client_addr, item.event_type, item.error_code, item.result]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(text)),
  )
})

async function load() {
  loading.value = true
  try {
    const data = await fetchAuthLog(limit.value)
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
        <h2>认证日志</h2>
        <p>AP_REQ 验证结果、远端地址和失败原因</p>
      </div>
      <el-button type="primary" :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
    </section>

    <section class="filter-bar">
      <el-input v-model="keyword" clearable placeholder="搜索 Client / IP / 错误码" :prefix-icon="Search" />
      <el-input-number v-model="limit" :min="10" :max="1000" :step="10" controls-position="right" />
    </section>

    <section class="panel">
      <el-table v-loading="loading" :data="filteredLogs" stripe>
        <el-table-column label="时间" min-width="180">
          <template #default="{ row }">{{ formatTime(row.time || row.ts) }}</template>
        </el-table-column>
        <el-table-column prop="client_id" label="Client" min-width="130" />
        <el-table-column prop="client_addr" label="Remote" min-width="170" />
        <el-table-column prop="event_type" label="事件" width="120" />
        <el-table-column label="RSA" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="row.rsa_verify_result === 'fail' ? 'danger' : 'success'">
              {{ row.rsa_verify_result || 'n/a' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="结果" width="100">
          <template #default="{ row }">
            <el-tag :type="tagTypeForResult(row.result)">{{ row.result || '-' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="error_code" label="错误码" min-width="150" />
      </el-table>
    </section>
  </div>
</template>
