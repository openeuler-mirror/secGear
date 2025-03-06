<script setup lang="ts">
import notFoundImg from '@/assets/category/illustrations/404.png';

</script>

<template>
  <div class="nofound">
    <img class="nofound-img" :src="notFoundImg" alt="404" />
    <p class="nofound-text">
      <slot name="title">404</slot>
    </p>
  </div>
</template>

<style lang="scss" scoped>
.nofound {
  display: flex;
  justify-content: center;
  align-items: center;
  flex-direction: column;
  color: var(--o-color-info1);
  min-height: calc(100vh - 339px);

  .nofound-text {
    margin-top: 16px;
    @include text2;
  }

  .nofound-img {
    height: 300px;
  }
}
</style>
