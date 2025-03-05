<script setup lang="ts">
import { ref, watch, type PropType } from 'vue';
import type { NavOptionT } from '@/@types/type-components';
import { useRoute, useRouter } from 'vue-router';

const props = defineProps({
  options: {
    type: Array as PropType<NavOptionT[]>,
    default: () => [],
  },
});

const router = useRouter();
const route = useRoute();
const navActiveId = ref('');

watch(
  () => route.path,
  (val) => {
    const item = props.options.find((el) => val.startsWith(el.path));
    if (item) {
      navActiveId.value = item.id;
    }
  }
);

const goPage = (item: NavOptionT) => {
  navActiveId.value = item.id;
  router.push({
    path: item.path,
  });
};
</script>

<template>
  <nav class="header-nav">
    <ul class="nav-list">
      <li
        v-for="item in options"
        :key="item.id"
        class="nav-item"
        :class="{
          active: navActiveId === item.id,
        }"
        @click="goPage(item)"
      >
        {{ item.label }}
      </li>
    </ul>
  </nav>
</template>

<style lang="scss" scoped>
.header-nav {
  height: 100%;
  position: relative;

  .nav-list {
    height: 100%;
    padding: 0;
    margin: 0;

    li {
      position: relative;
      display: inline-flex;
      align-items: center;
      height: 100%;
      color: var(--o-color-info1);
      cursor: pointer;
      transition: all var(--o-duration-s) var(--o-easing-standard);
      @include text1;

      @include hover {
        z-index: 99;
      }

      &::after {
        content: '';
        position: absolute;
        opacity: 0;
        bottom: 0;
        width: 100%;
        height: 2px;
        border-radius: 1px;
        background: var(--o-color-primary1);
        transition: all var(--o-duration-s) var(--o-easing-standard);
      }

      &.active {
        color: var(--o-color-primary1);
        z-index: 99;
        font-weight: 500;
        &::after {
          content: '';
          opacity: 1;
        }
      }
    }

    li:not(:last-child) {
      margin-right: var(--o-gap-6);

      @include respond-to('<=laptop') {
        margin-right: var(--o-gap-4);
      }
    }
  }
}
</style>
