<script setup>
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Check, Search } from '@element-plus/icons-vue'
import { fetchCertificate, verifyCertificate } from '../api/verify'
import { shortHash } from '../utils/format'

const loading = ref(false)
const verifying = ref(false)
const certId = ref(localStorage.getItem('v-webui-cert-id') || 'CLIENT_1')
const cert = ref(null)
const verifyResult = ref(null)

const modulusPreview = computed(() => shortHash(cert.value?.public_key?.n, 24))
const signaturePreview = computed(() => shortHash(cert.value?.sign, 24))

async function load() {
  const id = certId.value.trim()
  if (!id) {
    ElMessage.warning('请输入证书 ID')
    return
  }
  localStorage.setItem('v-webui-cert-id', id)
  loading.value = true
  verifyResult.value = null
  try {
    cert.value = await fetchCertificate(id)
  } catch (error) {
    cert.value = null
    ElMessage.error(error.message || String(error))
  } finally {
    loading.value = false
  }
}

async function verify() {
  const id = certId.value.trim()
  if (!id) {
    ElMessage.warning('请输入证书 ID')
    return
  }
  verifying.value = true
  try {
    verifyResult.value = await verifyCertificate(id)
    if (verifyResult.value.result === 'ok') {
      ElMessage.success('证书验证通过')
    } else {
      ElMessage.error(verifyResult.value.reason || '证书验证失败')
    }
  } catch (error) {
    ElMessage.error(error.message || String(error))
  } finally {
    verifying.value = false
  }
}
</script>

<template>
  <div class="page-stack">
    <section class="toolbar-row">
      <div>
        <h2>证书</h2>
        <p>客户端证书查看与签名验证</p>
      </div>
      <div class="toolbar-actions">
        <el-input v-model="certId" clearable placeholder="CLIENT_1" :prefix-icon="Search" @keyup.enter="load" />
        <el-button type="primary" :loading="loading" @click="load">读取</el-button>
        <el-button :icon="Check" :loading="verifying" @click="verify">验证</el-button>
      </div>
    </section>

    <section v-if="verifyResult" class="verify-result">
      <el-alert
        :type="verifyResult.result === 'ok' ? 'success' : 'error'"
        :title="verifyResult.result === 'ok' ? '验证通过' : '验证失败'"
        :description="verifyResult.reason || verifyResult.id"
        show-icon
        :closable="false"
      />
    </section>

    <section class="panel">
      <el-skeleton v-if="loading" :rows="8" animated />
      <el-empty v-else-if="!cert" description="暂无证书数据" />
      <div v-else class="cert-layout">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="ID">{{ cert.id || '-' }}</el-descriptions-item>
          <el-descriptions-item label="Issuer">{{ cert.issuer || '-' }}</el-descriptions-item>
          <el-descriptions-item label="Expire">{{ cert.expire || '-' }}</el-descriptions-item>
          <el-descriptions-item label="Exponent">{{ cert.public_key?.e || '-' }}</el-descriptions-item>
          <el-descriptions-item label="Modulus" :span="2">
            <code class="inline-code wrap">{{ modulusPreview }}</code>
          </el-descriptions-item>
          <el-descriptions-item label="Signature" :span="2">
            <code class="inline-code wrap">{{ signaturePreview }}</code>
          </el-descriptions-item>
        </el-descriptions>

        <div class="key-block">
          <span>RSA N</span>
          <pre>{{ cert.public_key?.n || '-' }}</pre>
        </div>
      </div>
    </section>
  </div>
</template>
