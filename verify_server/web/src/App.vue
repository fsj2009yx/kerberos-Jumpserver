<script setup>
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import {
  Connection,
  DataAnalysis,
  DocumentChecked,
  FolderOpened,
  Key,
  Monitor,
  Operation,
  Tickets,
  VideoPlay,
} from '@element-plus/icons-vue'
import { getApiBase, setApiBase } from './api/verify'

const route = useRoute()
const apiBase = ref(getApiBase())

const navItems = [
  { path: '/overview', label: '概览', icon: Monitor },
  { path: '/sessions', label: '活跃会话', icon: Connection },
  { path: '/frames', label: 'PTY Frames', icon: Tickets },
  { path: '/auth', label: '认证日志', icon: DocumentChecked },
  { path: '/audit-session', label: '会话审计', icon: DataAnalysis },
  { path: '/replay', label: '输出回放', icon: VideoPlay },
  { path: '/targets', label: 'SSH 节点', icon: FolderOpened },
  { path: '/certificates', label: '证书', icon: Key },
]

const activePath = computed(() => route.path)
const title = computed(() => route.meta.title || 'Verify Server')

watch(apiBase, (value) => {
  setApiBase(value)
})
</script>

<template>
  <el-container class="app-shell">
    <el-aside width="236px" class="app-aside">
      <div class="brand">
        <span class="brand-mark">V</span>
        <div>
          <strong>Verify Server</strong>
          <span>Web Console</span>
        </div>
      </div>

      <el-menu :default-active="activePath" router class="side-menu">
        <el-menu-item v-for="item in navItems" :key="item.path" :index="item.path">
          <el-icon><component :is="item.icon" /></el-icon>
          <span>{{ item.label }}</span>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <el-container>
      <el-header class="app-header">
        <div>
          <span class="section-kicker">V Server</span>
          <h1>{{ title }}</h1>
        </div>
        <div class="header-tools">
          <el-input
            v-model="apiBase"
            clearable
            placeholder="API Base"
            :prefix-icon="Operation"
          />
        </div>
      </el-header>

      <el-main class="app-main">
        <RouterView />
      </el-main>
    </el-container>
  </el-container>
</template>
