<script setup>
import { computed, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Close, Hide, Lock, Plus, Refresh, View } from '@element-plus/icons-vue'
import {
  fetchTargetPassword,
  fetchTargets,
  saveTarget,
  updateTargetBlockedClients,
} from '../api/verify'

const loading = ref(false)
const saving = ref(false)
const targets = ref([])
const passwordVisible = reactive({})
const passwordValues = reactive({})
const blockEditors = reactive({})
const form = reactive({
  id: '',
  host: '',
  port: 22,
  ssh_user: '',
  auth_type: 'password',
  password: '',
  key_path: '',
  known_hosts_path: '',
  blocked_clients_text: '',
})

const targetCount = computed(() => targets.value.length)

function parseClientText(value) {
  return String(value || '')
    .split(/[\s,，]+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function resetForm() {
  Object.assign(form, {
    id: '',
    host: '',
    port: 22,
    ssh_user: '',
    auth_type: 'password',
    password: '',
    key_path: '',
    known_hosts_path: '',
    blocked_clients_text: '',
  })
}

async function load() {
  loading.value = true
  try {
    const data = await fetchTargets()
    targets.value = data.targets || []
  } catch (error) {
    ElMessage.error(error.message || String(error))
  } finally {
    loading.value = false
  }
}

async function submit() {
  if (!form.id.trim() || !form.host.trim() || !form.ssh_user.trim()) {
    ElMessage.warning('请填写节点 ID、Host 和 SSH 用户')
    return
  }
  saving.value = true
  try {
    await saveTarget({
      id: form.id.trim(),
      host: form.host.trim(),
      port: Number(form.port) || 22,
      ssh_user: form.ssh_user.trim(),
      auth_type: form.auth_type,
      password: form.password,
      key_path: form.key_path.trim(),
      known_hosts_path: form.known_hosts_path.trim(),
      blocked_clients: parseClientText(form.blocked_clients_text),
    })
    ElMessage.success('SSH 节点已保存')
    resetForm()
    await load()
  } catch (error) {
    ElMessage.error(error.message || String(error))
  } finally {
    saving.value = false
  }
}

async function togglePassword(target) {
  if (passwordVisible[target.id]) {
    passwordVisible[target.id] = false
    return
  }
  if (!target.password_set) {
    ElMessage.warning('该节点没有存储密码')
    return
  }
  try {
    const data = await fetchTargetPassword(target.id)
    passwordValues[target.id] = data.password || ''
    passwordVisible[target.id] = true
  } catch (error) {
    ElMessage.error(error.message || String(error))
  }
}

function openBlockEditor(target) {
  blockEditors[target.id] = {
    open: true,
    text: (target.blocked_clients || []).join('\n'),
  }
}

function closeBlockEditor(target) {
  blockEditors[target.id] = { open: false, text: '' }
}

async function saveBlocked(target) {
  const editor = blockEditors[target.id]
  if (!editor) return
  try {
    const blocked = parseClientText(editor.text)
    await updateTargetBlockedClients(target.id, blocked)
    ElMessage.success('封禁列表已更新')
    closeBlockEditor(target)
    await load()
  } catch (error) {
    ElMessage.error(error.message || String(error))
  }
}

load()
</script>

<template>
  <div class="page-stack">
    <section class="toolbar-row">
      <div>
        <h2>SSH 节点</h2>
        <p>节点注册、凭据查看和 CLIENT 封禁管理</p>
      </div>
      <div class="toolbar-actions">
        <el-tag type="info">{{ targetCount }} nodes</el-tag>
        <el-button :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h3>注册节点</h3>
      </div>
      <el-form class="target-form" label-position="top">
        <el-form-item label="节点 ID">
          <el-input v-model="form.id" placeholder="prod-1" />
        </el-form-item>
        <el-form-item label="Host">
          <el-input v-model="form.host" placeholder="127.0.0.1" />
        </el-form-item>
        <el-form-item label="Port">
          <el-input-number v-model="form.port" :min="1" :max="65535" controls-position="right" />
        </el-form-item>
        <el-form-item label="SSH 用户">
          <el-input v-model="form.ssh_user" placeholder="deploy" />
        </el-form-item>
        <el-form-item label="认证方式">
          <el-segmented v-model="form.auth_type" :options="['password', 'private_key']" />
        </el-form-item>
        <el-form-item v-if="form.auth_type === 'password'" label="密码">
          <el-input v-model="form.password" type="password" show-password autocomplete="new-password" />
        </el-form-item>
        <el-form-item v-else label="私钥路径">
          <el-input v-model="form.key_path" placeholder="./keys/ssh/id_rsa" />
        </el-form-item>
        <el-form-item label="Known Hosts">
          <el-input v-model="form.known_hosts_path" placeholder="./keys/ssh/known_hosts" />
        </el-form-item>
        <el-form-item label="封禁 CLIENT">
          <el-input v-model="form.blocked_clients_text" type="textarea" :rows="2" placeholder="CLIENT_3, CLIENT_4" />
        </el-form-item>
        <div class="target-form-actions">
          <el-button :icon="Plus" type="primary" :loading="saving" @click="submit">保存节点</el-button>
          <el-button @click="resetForm">清空</el-button>
        </div>
      </el-form>
    </section>

    <section class="target-list">
      <el-skeleton v-if="loading" :rows="8" animated />
      <el-empty v-else-if="targets.length === 0" description="暂无 SSH 节点" />

      <template v-else>
        <article v-for="target in targets" :key="target.id" class="target-card">
          <div class="target-card-main">
            <div class="target-card-head">
              <div>
                <h3>{{ target.id }}</h3>
                <span>{{ target.host }}:{{ target.port }}</span>
              </div>
              <div class="target-card-actions">
                <el-button :icon="passwordVisible[target.id] ? Hide : View" circle @click="togglePassword(target)" />
                <el-button :icon="Lock" circle @click="openBlockEditor(target)" />
              </div>
            </div>

            <dl class="target-fields">
              <div>
                <dt>SSH User</dt>
                <dd>{{ target.ssh_user || '-' }}</dd>
              </div>
              <div>
                <dt>Auth</dt>
                <dd>{{ target.auth_type || '-' }}</dd>
              </div>
              <div>
                <dt>Password</dt>
                <dd class="target-password">
                  <code>{{ passwordVisible[target.id] ? passwordValues[target.id] : (target.password_set ? '********' : '-') }}</code>
                </dd>
              </div>
              <div>
                <dt>Blocked</dt>
                <dd>
                  <el-tag v-if="(target.blocked_clients || []).length === 0" type="success">none</el-tag>
                  <el-tag v-for="client in target.blocked_clients || []" v-else :key="client" type="danger">
                    {{ client }}
                  </el-tag>
                </dd>
              </div>
            </dl>
          </div>

          <div v-if="blockEditors[target.id]?.open" class="target-mask">
            <div class="target-mask-panel">
              <div class="target-mask-head">
                <strong>{{ target.id }} 封禁 CLIENT</strong>
                <el-button :icon="Close" circle @click="closeBlockEditor(target)" />
              </div>
              <el-input
                v-model="blockEditors[target.id].text"
                type="textarea"
                :rows="6"
                placeholder="每行一个 CLIENT_ID，或用逗号分隔"
              />
              <div class="target-mask-actions">
                <el-button @click="closeBlockEditor(target)">取消</el-button>
                <el-button type="primary" @click="saveBlocked(target)">保存</el-button>
              </div>
            </div>
          </div>
        </article>
      </template>
    </section>
  </div>
</template>
