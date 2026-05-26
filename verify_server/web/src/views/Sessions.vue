<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { fetchSessions } from '../api/verify'
import { formatTime } from '../utils/format'

const loading = ref(false)
const sessions = ref([])
const query = ref('')

const rows = computed(() => {
  const text = query.value.trim().toLowerCase()
  return sessions.value.filter((item) => {
    if (!text) {
      return true
    }
    return [item.client_id, item.pty_session_id, item.client_addr, item.target_id, item.k_cv_sha256]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(text))
  })
})

function isExpired(row) {
  return Number(row.expire_at || 0) * 1000 < Date.now()
}

async function load() {
  loading.value = true
  try {
    const data = await fetchSessions()
    sessions.value = data?.sessions || []
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
        <h2>活跃会话</h2>
        <p>当前通过 AP 认证并保留在 V 服务内存中的连接</p>
      </div>
      <div class="toolbar-actions">
        <el-input v-model="query" clearable placeholder="搜索 Client / PTY / Key" />
        <el-button type="primary" :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
      </div>
    </section>

    <section class="panel">
      <el-table v-loading="loading" :data="rows" stripe>
        <el-table-column prop="client_id" label="Client" min-width="140" />
        <el-table-column prop="client_addr" label="Remote" min-width="170" />
        <el-table-column prop="target_id" label="Target" min-width="120" />
        <el-table-column prop="pty_session_id" label="PTY" width="90" />
        <el-table-column label="Frames" width="110">
          <template #default="{ row }">{{ row.total_frames || 0 }}</template>
        </el-table-column>
        <el-table-column label="Last IO" min-width="170">
          <template #default="{ row }">{{ formatTime(row.last_io_ts) }}</template>
        </el-table-column>
        <el-table-column label="Expire" min-width="170">
          <template #default="{ row }">{{ formatTime(row.expire_at) }}</template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="isExpired(row) ? 'danger' : 'success'">
              {{ isExpired(row) ? '过期' : '有效' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Key SHA256" min-width="150">
          <template #default="{ row }">
            <code class="inline-code">{{ row.k_cv_sha256 || '-' }}</code>
          </template>
        </el-table-column>
      </el-table>
    </section>
  </div>
</template>
