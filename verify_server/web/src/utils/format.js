export function formatTime(value) {
  if (!value) {
    return '-'
  }
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value)
  if (Number.isNaN(date.getTime())) {
    return '-'
  }
  return date.toLocaleString()
}

export function formatDuration(seconds) {
  const total = Number(seconds) || 0
  const days = Math.floor(total / 86400)
  const hours = Math.floor((total % 86400) / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  if (days > 0) {
    return `${days}d ${hours}h`
  }
  if (hours > 0) {
    return `${hours}h ${minutes}m`
  }
  return `${minutes}m ${total % 60}s`
}

export function formatBytes(bytes) {
  const value = Number(bytes) || 0
  if (value < 1024) {
    return `${value} B`
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`
  }
  return `${(value / 1024 / 1024).toFixed(1)} MB`
}

export function decodeBase64(value) {
  if (!value) {
    return ''
  }
  try {
    const binary = window.atob(value)
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0))
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
  } catch {
    return ''
  }
}

export function shortHash(value, size = 10) {
  if (!value) {
    return '-'
  }
  if (value.length <= size * 2 + 3) {
    return value
  }
  return `${value.slice(0, size)}...${value.slice(-size)}`
}

export function tagTypeForResult(result) {
  if (result === 'ok') {
    return 'success'
  }
  if (result === 'fail') {
    return 'danger'
  }
  return 'info'
}

export function tagTypeForDirection(direction) {
  if (direction === 'C->V') {
    return 'primary'
  }
  if (direction === 'V->C') {
    return 'warning'
  }
  return 'info'
}

export function frameTitle(record) {
  return record.frame_type || record.event_type || record.kind || 'frame'
}
