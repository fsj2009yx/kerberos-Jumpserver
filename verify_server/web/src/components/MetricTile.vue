<script setup>
defineProps({
  label: { type: String, required: true },
  value: { type: [String, Number], default: '-' },
  meta: { type: String, default: '' },
  tone: { type: String, default: 'neutral' },
})
</script>

<template>
  <section class="metric-tile" :class="`tone-${tone}`">
    <span class="metric-label">{{ label }}</span>
    <strong>{{ value }}</strong>
    <span v-if="meta" class="metric-meta">{{ meta }}</span>
  </section>
</template>
