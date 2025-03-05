<script setup lang="ts">
import { OConfigProvider } from '@opensig/opendesign';
import zhCN from '@opensig/opendesign/es/locale/lang/zh-cn';
import AppHeader from '@/components/header/AppHeader.vue';
import AppFooter from '@/components/AppFooter.vue';
</script>

<template>
  <OConfigProvider :locale="zhCN">
    <AppHeader />
    <main class="ly-main">
      <RouterView />
    </main>
    <AppFooter />
  </OConfigProvider>
</template>

<style lang="scss" scoped>
.ly-main {
  min-height: calc(100vh - 259px);
  padding-top: var(--layout-header-height);
}
</style>

<style lang="scss">
#app {
  --layout-content-max-width: 1544px;
  --layout-content-padding: 80px;
  --layout-header-height: 80px;

  min-width: 1200px;
  color: var(--o-color-info1);

  @include respond-to('<=laptop') {
    --layout-content-max-width: 100%;
    --layout-content-padding: 40px;
  }

  @include respond-to('<=pad') {
    --layout-content-padding: 32px;
  }

  @include respond-to('phone') {
    --layout-content-padding: 24px;
  }
}
</style>
