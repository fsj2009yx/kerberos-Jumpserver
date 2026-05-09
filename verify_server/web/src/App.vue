<script setup>
import { computed, onMounted, reactive, ref } from 'vue'

const service = {
  code: 'V',
  title: 'Verify Server WebUI',
  subtitle: '应用服务器会话与审计接口',
  apiPort: 9885,
  source: 'verify_server/service/web_api.go',
}

const endpoints = [
  {
    id: 'status',
    method: 'GET',
    path: '/api/status',
    summary: 'V 节点状态',
    schema: '{ node_id, uptime_s, active_sessions, total_pty_frames, total_rejected_frames }',
    implemented: true,
  },
  {
    id: 'auth_log',
    method: 'GET',
    path: '/api/auth_log?limit=100',
    summary: 'AP 认证日志',
    schema: '{ logs: [{ ts, client_id, client_ip, result, rsa_verify_result }] }',
    implemented: false,
    note: '文档定义；当前 Go WebUI 未注册该 handler。',
  },
  {
    id: 'pty_log',
    method: 'GET',
    path: '/api/pty_log?limit=100',
    summary: 'PTY 帧执行日志',
    schema: '{ logs: [{ ts, client_id, pty_session_id, frame_type, frame_size, rsa_ok, result }] }',
    implemented: false,
    note: '文档定义；当前 Go WebUI 未注册该 handler。',
  },
  {
    id: 'sessions',
    method: 'GET',
    path: '/api/sessions',
    summary: '活跃 Session 列表',
    schema:
      '{ sessions: [{ client_id, client_ip, k_cv_sha256, expire_at, last_io_ts, total_frames, pty_session_id }] }',
    implemented: true,
  },
  {
    id: 'cert',
    method: 'GET',
    path: '/api/cert/:id',
    summary: '客户端证书',
    schema: '{ id, public_key: { n, e }, expire, sign }',
    implemented: false,
    needsCertId: true,
    note: '文档定义；当前 Go WebUI 未注册该 handler。',
  },
  {
    id: 'verify_cert',
    method: 'POST',
    path: '/api/verify_cert',
    summary: '手动验证证书',
    schema: '{ id, result: "ok" | "fail", reason }',
    implemented: false,
    note: '文档定义；当前 Go WebUI 未注册该 handler。',
  },
]

const apiBase = ref(localStorage.getItem('v-webui-api-base') || '')
const certId = ref(localStorage.getItem('v-webui-cert-id') || 'CLIENT_1')
const selectedId = ref(endpoints[0].id)
const responses = reactive({})

for (const endpoint of endpoints) {
  responses[endpoint.id] = {
    loading: false,
    status: null,
    ok: null,
    body: '',
    error: '',
    updatedAt: '',
  }
}

const selectedEndpoint = computed(() => endpoints.find((endpoint) => endpoint.id === selectedId.value))
const selectedResponse = computed(() => responses[selectedId.value])
const implementedCount = computed(() => endpoints.filter((endpoint) => endpoint.implemented).length)

function saveSettings() {
  localStorage.setItem('v-webui-api-base', apiBase.value.trim())
  localStorage.setItem('v-webui-cert-id', certId.value.trim())
}

function endpointPath(endpoint) {
  if (endpoint.needsCertId) {
    return `/api/cert/${encodeURIComponent(certId.value.trim() || 'CLIENT_1')}`
  }
  return endpoint.path
}

function endpointUrl(endpoint) {
  const base = apiBase.value.trim().replace(/\/+$/, '')
  const path = endpointPath(endpoint)
  return base ? `${base}${path}` : path
}

function formatBody(text) {
  if (!text) {
    return '(empty response)'
  }
  try {
    return JSON.stringify(JSON.parse(text), null, 2)
  } catch {
    return text
  }
}

async function requestEndpoint(endpoint) {
  if (!endpoint?.implemented) {
    return
  }

  saveSettings()
  const state = responses[endpoint.id]
  state.loading = true
  state.error = ''
  state.status = null
  state.ok = null

  try {
    const response = await fetch(endpointUrl(endpoint), {
      method: endpoint.method,
      headers: {
        Accept: 'application/json',
      },
    })
    const text = await response.text()
    state.status = response.status
    state.ok = response.ok
    state.body = formatBody(text)
    state.updatedAt = new Date().toLocaleTimeString()
    if (!response.ok) {
      state.error = `HTTP ${response.status}`
    }
  } catch (error) {
    state.error = error instanceof Error ? error.message : String(error)
    state.body = ''
    state.updatedAt = new Date().toLocaleTimeString()
  } finally {
    state.loading = false
  }
}

async function refreshImplemented() {
  for (const endpoint of endpoints.filter((item) => item.implemented)) {
    await requestEndpoint(endpoint)
  }
}

onMounted(() => {
  refreshImplemented()
})
</script>

<template>
  <div class="shell">
    <header class="topbar">
      <div>
        <p class="eyebrow">{{ service.code }}</p>
        <h1>{{ service.title }}</h1>
        <p class="subtitle">{{ service.subtitle }}</p>
      </div>
      <div class="meta">
        <span>Go WebUI :{{ service.apiPort }}</span>
        <span>{{ implementedCount }}/{{ endpoints.length }} 已实现</span>
        <span>{{ service.source }}</span>
      </div>
    </header>

    <section class="controls" aria-label="API controls">
      <label>
        <span>API Base</span>
        <input
          v-model="apiBase"
          type="text"
          placeholder="留空使用 /api 代理"
          @change="saveSettings"
        />
      </label>
      <label>
        <span>证书 ID</span>
        <input v-model="certId" type="text" @change="saveSettings" />
      </label>
      <button type="button" :disabled="responses.status.loading" @click="refreshImplemented">
        刷新已实现接口
      </button>
    </section>

    <main class="layout">
      <section class="endpoint-list" aria-label="Endpoint list">
        <button
          v-for="endpoint in endpoints"
          :key="endpoint.id"
          type="button"
          class="endpoint"
          :class="{ active: endpoint.id === selectedId }"
          @click="selectedId = endpoint.id"
        >
          <span class="method">{{ endpoint.method }}</span>
          <span class="path">{{ endpoint.path }}</span>
          <span class="summary">{{ endpoint.summary }}</span>
          <span class="badge" :class="endpoint.implemented ? 'ok' : 'planned'">
            {{ endpoint.implemented ? '当前可调用' : '文档规划' }}
          </span>
        </button>
      </section>

      <section v-if="selectedEndpoint" class="detail">
        <div class="detail-head">
          <div>
            <span class="method large">{{ selectedEndpoint.method }}</span>
            <h2>{{ selectedEndpoint.path }}</h2>
          </div>
          <button
            type="button"
            :disabled="!selectedEndpoint.implemented || selectedResponse.loading"
            @click="requestEndpoint(selectedEndpoint)"
          >
            {{ selectedResponse.loading ? '请求中' : '发送请求' }}
          </button>
        </div>

        <dl class="spec">
          <div>
            <dt>说明</dt>
            <dd>{{ selectedEndpoint.summary }}</dd>
          </div>
          <div>
            <dt>实际 URL</dt>
            <dd>{{ endpointUrl(selectedEndpoint) }}</dd>
          </div>
          <div>
            <dt>返回字段</dt>
            <dd>{{ selectedEndpoint.schema }}</dd>
          </div>
          <div v-if="selectedEndpoint.note">
            <dt>状态</dt>
            <dd>{{ selectedEndpoint.note }}</dd>
          </div>
        </dl>

        <div class="response-head">
          <span>响应</span>
          <span v-if="selectedResponse.updatedAt">更新 {{ selectedResponse.updatedAt }}</span>
          <span v-if="selectedResponse.status" :class="selectedResponse.ok ? 'text-ok' : 'text-error'">
            HTTP {{ selectedResponse.status }}
          </span>
          <span v-if="selectedResponse.error" class="text-error">{{ selectedResponse.error }}</span>
        </div>
        <pre>{{ selectedResponse.body || '暂无响应' }}</pre>
      </section>
    </main>
  </div>
</template>
