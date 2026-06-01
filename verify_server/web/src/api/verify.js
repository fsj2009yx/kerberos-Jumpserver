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

function withQuery(path, params = {}) {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      query.set(key, String(value).trim())
    }
  }
  const suffix = query.toString()
  return suffix ? `${path}?${suffix}` : path
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

export function fetchPtyLog(limit = 100, filters = {}) {
  return requestJSON(withQuery('/api/pty_log', { limit, ...filters }))
}

export function fetchAuditFrames(clientId, targetId, limit = 300) {
  return requestJSON(withQuery('/api/audit/frames', { client_id: clientId, target_id: targetId, limit }))
}

export function fetchReplay(clientId, targetId, limit = 300) {
  return requestJSON(withQuery('/api/audit/replay', { client_id: clientId, target_id: targetId, limit }))
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

export function fetchTargets() {
  return requestJSON('/api/targets')
}

export function saveTarget(target) {
  return requestJSON('/api/targets', {
    method: 'POST',
    body: JSON.stringify(target),
  })
}

export function fetchTargetPassword(id) {
  return requestJSON(`/api/targets/${encodeURIComponent(id)}/password`)
}

export function updateTargetBlockedClients(id, blockedClients) {
  return requestJSON(`/api/targets/${encodeURIComponent(id)}/blocked_clients`, {
    method: 'PUT',
    body: JSON.stringify({ blocked_clients: blockedClients }),
  })
}
