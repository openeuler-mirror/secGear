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
    --layout-header-height: 48px;
    --layout-content-padding: 32px;
  }

  @include respond-to('phone') {
    --layout-content-padding: 24px;
  }
}

.header-user-dropdown-item {
  min-width: 144px;
  --dropdown-item-radius: 4px;

  @include hover {
    color: var(--o-color-link1);
  }
}

.dlg-form {
  .o-form-item.align-center-form-item {
    line-height: var(--o-control_size-l);
  }
  .o-form-item-label {
    margin-top: 0;
    margin-bottom: 0;
  }
  .upload-form-item {
    &:not(.selected-file) {
      .o-form-item-label {
        margin-top: 0;
        margin-bottom: 0;
        line-height: var(--o-control_size-l);
      }
    }

    &.selected-file {
      .o-upload-row-item {
        background-color: var(--upload-item-bg-hover);
      }
      .o-form-item-main-wrap {
        display: block;
      }
      .o-upload-select-wrap {
        display: none;
      }
      .o-upload-row-item {
        margin-top: 0;
      }
    }
  }
}
</style>
