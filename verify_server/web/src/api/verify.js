const API_BASE_KEY = 'v-webui-api-base'

export function getApiBase() {
  return localStorage.getItem(API_BASE_KEY) || ''
}

export function setApiBase(value) {
  localStorage.setItem(API_BASE_KEY, String(value || '').trim())
}

function apiURL(path) {
  const base = getApiBase().replace(/\/+$/, '')
  return base ? `${base}${path}` : path
}

async function requestJSON(path, options = {}) {
  const response = await fetch(apiURL(path), {
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  })
  const text = await response.text()
  const data = text ? JSON.parse(text) : null
  if (!response.ok) {
    const error = new Error(data?.error || `HTTP ${response.status}`)
    error.status = response.status
    error.data = data
    throw error
  }
  return data
}

function withLimit(path, limit) {
  const nextLimit = Number(limit) || 100
  return `${path}?limit=${encodeURIComponent(nextLimit)}`
}

export function fetchStatus() {
  return requestJSON('/api/status')
}

export function fetchSessions() {
  return requestJSON('/api/sessions')
}

export function fetchAuthLog(limit = 100) {
  return requestJSON(withLimit('/api/auth_log', limit))
}

export function fetchPtyLog(limit = 100) {
  return requestJSON(withLimit('/api/pty_log', limit))
}

export function fetchAuditSession(id, limit = 200) {
  return requestJSON(withLimit(`/api/audit/session/${encodeURIComponent(id)}`, limit))
}

export function fetchReplay(id, limit = 300) {
  return requestJSON(withLimit(`/api/audit/replay/${encodeURIComponent(id)}`, limit))
}

export function fetchCertificate(id) {
  return requestJSON(`/api/cert/${encodeURIComponent(id)}`)
}

export function verifyCertificate(id) {
  return requestJSON('/api/verify_cert', {
    method: 'POST',
    body: JSON.stringify({ id }),
  })
}
