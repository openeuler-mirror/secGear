<script setup lang="ts">
import ContentWrapper from '@/components/ContentWrapper.vue';
import HeaderNav from '@/components/header/HeaderNav.vue';
import HeaderUser from '@/components/header/HeaderUser.vue';

import logo from '@/assets/category/header/logo.svg';
import navs from '@/config/navs';
import { OPEN_EULER_LINK } from '@/config/common';
</script>

<template>
  <header class="app-header">
    <ContentWrapper class="app-header-wrap">
      <a :href="OPEN_EULER_LINK">
        <img class="logo" alt="openEuler logo" :src="logo" />
      </a>
      <HeaderNav :options="navs" />
      <HeaderUser />
    </ContentWrapper>
  </header>
</template>

<style lang="scss" scoped>
.app-header {
  background-color: var(--o-color-fill2);
  position: fixed;
  left: 0;
  right: 0;
  top: 0;
  z-index: 98;
  box-shadow: var(--o-shadow-1);
  backdrop-filter: blur(5px);

  @include respond-to('>pad_v') {
    &.dark {
      &:after {
        content: '';
        position: absolute;
        left: 0;
        right: 0;
        bottom: 0;
        height: 1px;
        background-color: var(--o-color-control4);
      }
    }

    &:before {
      bottom: 0;
      box-shadow: var(--o-shadow-1);
      content: '';
      left: 0;
      pointer-events: none;
      position: absolute;
      right: 0;
      top: 0;
      z-index: 100;
    }
  }

  .app-header-wrap {
    display: flex;
    align-items: center;

    @include respond-to('>pad_v') {
      height: 72px;
    }

    @include respond-to('<=pad_v') {
      height: 48px;
      justify-content: space-between;
      position: relative;
    }
  }

  .header-nav {
    flex: 1;
    padding-right: 16px;
  }

  .logo {
    cursor: pointer;

    @include respond-to('>pad_v') {
      height: 32px;
      width: 136px;
      margin-right: var(--o-gap-7);

      @include respond-to('laptop') {
        margin-right: 28px;
      }

      @include respond-to('pad_h') {
        margin-right: 24px;
      }
    }

    @include respond-to('<=pad_v') {
      height: 24px;
      width: 136px;
      position: absolute;
      left: 50%;
      transform: translateX(-50%);
      top: 12px;
    }
  }
}
</style>
