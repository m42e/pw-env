<script setup lang="ts">
import { ref, onMounted } from "vue";

const stars = ref<number | null>(null);
const version = ref<string | null>(null);

onMounted(async () => {
  try {
    const [repoRes, releaseRes] = await Promise.all([
      fetch("https://api.github.com/repos/m42e/pw-env"),
      fetch("https://api.github.com/repos/m42e/pw-env/releases/latest"),
    ]);
    if (repoRes.ok) {
      const data = await repoRes.json();
      stars.value = data.stargazers_count;
    }
    if (releaseRes.ok) {
      const data = await releaseRes.json();
      version.value = data.tag_name;
    }
  } catch {
    // silently ignore network errors
  }
});
</script>

<template>
  <div class="gh-nav-strip">
    <a
      v-if="version"
      class="gh-version-badge"
      :href="`https://github.com/m42e/pw-env/releases/tag/${version}`"
      target="_blank"
      rel="noopener noreferrer"
      :aria-label="`Latest release ${version}`"
    >{{ version }}</a>
    <a
      class="gh-star-btn"
      href="https://github.com/m42e/pw-env"
      target="_blank"
      rel="noopener noreferrer"
      aria-label="Star pw-env on GitHub"
    >
      <svg viewBox="0 0 16 16" width="13" height="13" aria-hidden="true" fill="currentColor">
        <path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.751.751 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25Z"/>
      </svg>
      <span>Star</span>
      <span v-if="stars !== null" class="gh-star-count">{{ stars.toLocaleString() }}</span>
    </a>
  </div>
</template>
