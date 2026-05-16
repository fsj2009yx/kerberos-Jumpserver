import { createRouter, createWebHashHistory } from 'vue-router'
import Overview from '../views/Overview.vue'
import Sessions from '../views/Sessions.vue'
import Frames from '../views/Frames.vue'
import AuthLog from '../views/AuthLog.vue'
import AuditSession from '../views/AuditSession.vue'
import Replay from '../views/Replay.vue'
import Certificates from '../views/Certificates.vue'

const routes = [
  { path: '/', redirect: '/overview' },
  { path: '/overview', name: 'overview', component: Overview, meta: { title: '概览' } },
  { path: '/sessions', name: 'sessions', component: Sessions, meta: { title: '活跃会话' } },
  { path: '/frames', name: 'frames', component: Frames, meta: { title: 'PTY Frames' } },
  { path: '/auth', name: 'auth-log', component: AuthLog, meta: { title: '认证日志' } },
  { path: '/audit-session', name: 'audit-session', component: AuditSession, meta: { title: '会话审计' } },
  { path: '/replay', name: 'replay', component: Replay, meta: { title: '输出回放' } },
  { path: '/certificates', name: 'certificates', component: Certificates, meta: { title: '证书' } },
]

export default createRouter({
  history: createWebHashHistory(),
  routes,
})
