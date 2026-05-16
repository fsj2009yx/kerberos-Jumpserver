<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { fetchAuthLog, fetchPtyLog, fetchSessions, fetchStatus } from '../api/verify'
import FrameCard from '../components/FrameCard.vue'
import MetricTile from '../components/MetricTile.vue'
import { formatDuration, formatTime } from '../utils/format'

const loading = ref(false)
const status = ref({})
const sessions = ref([])
const authLogs = ref([])
const ptyLogs = ref([])

const activeSessions = computed(() => status.value.active_sessions ?? sessions.value.length)
const recentFrames = computed(() => ptyLogs.value.slice(0, 4))
const recentAuth = computed(() => authLogs.value.slice(0, 6))

async function load() {
  loading.value = true
  try {
    const [statusData, sessionData, authData, ptyData] = await Promise.all([
      fetchStatus(),
      fetchSessions(),
      fetchAuthLog(30),
      fetchPtyLog(30),
    ])
    status.value = statusData || {}
    sessions.value = sessionData?.sessions || []
    authLogs.value = authData?.logs || []
    ptyLogs.value = ptyData?.logs || []
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
        <h2>节点状态</h2>
        <p>当前运行指标与最近审计流</p>
      </div>
      <el-button type="primary" :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
    </section>

    <section class="metrics-grid">
      <MetricTile label="节点" :value="status.node_id || '-'" meta="verify_server" tone="green" />
      <MetricTile label="运行时间" :value="formatDuration(status.uptime_s)" meta="uptime" tone="blue" />
      <MetricTile label="活跃会话" :value="activeSessions" meta="sessions" tone="amber" />
      <MetricTile label="PTY Frames" :value="status.total_pty_frames ?? 0" meta="total" tone="rose" />
    </section>

    <section class="content-grid two-col">
      <div class="panel">
        <div class="panel-head">
          <h3>活跃会话</h3>
          <el-button text type="primary" @click="$router.push('/sessions')">查看全部</el-button>
        </div>
        <el-table :data="sessions.slice(0, 6)" stripe height="300">
          <el-table-column prop="client_id" label="Client" min-width="130" />
          <el-table-column prop="pty_session_id" label="PTY" width="88" />
          <el-table-column label="Frames" width="110">
            <template #default="{ row }">{{ row.total_frames || 0 }}</template>
          </el-table-column>
          <el-table-column label="Last IO" min-width="150">
            <template #default="{ row }">{{ formatTime(row.last_io_ts) }}</template>
          </el-table-column>
        </el-table>
      </div>

      <div class="panel">
        <div class="panel-head">
          <h3>认证结果</h3>
          <el-button text type="primary" @click="$router.push('/auth')">查看日志</el-button>
        </div>
        <el-timeline class="auth-timeline">
          <el-timeline-item
            v-for="item in recentAuth"
            :key="item.id"
            :type="item.result === 'ok' ? 'success' : 'danger'"
            :timestamp="formatTime(item.time || item.ts)"
          >
            <div class="timeline-line">
              <strong>{{ item.client_id || 'unknown' }}</strong>
              <el-tag size="small" :type="item.result === 'ok' ? 'success' : 'danger'">
                {{ item.result }}
              </el-tag>
            </div>
            <span class="muted">{{ item.error_code || item.event_type }}</span>
          </el-timeline-item>
        </el-timeline>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h3>最近 PTY Frames</h3>
        <el-button text type="primary" @click="$router.push('/frames')">查看全部</el-button>
      </div>
      <div class="frame-list compact">
        <FrameCard v-for="record in recentFrames" :key="record.id" :record="record" />
        <el-empty v-if="recentFrames.length === 0 && !loading" description="暂无 PTY frame" />
      </div>
    </section>
  </div>
</template>
