<script setup lang="ts">
import { isBoolean, isString, isUndefined } from '@opensig/opendesign';
import { computed } from 'vue';

const DEFAULT = Symbol('default');

interface ContentWrapperPropsT {
  verticalPadding?: boolean | string | Array<string>;
}

const props = withDefaults(defineProps<ContentWrapperPropsT>(), {
  verticalPadding: undefined,
});

const paddingTop = computed(() => {
  if (!props.verticalPadding) {
    return 0;
  }

  if (isBoolean(props.verticalPadding)) {
    return DEFAULT;
  } else if (isString(props.verticalPadding)) {
    return props.verticalPadding;
  } else {
    return props.verticalPadding[0];
  }
});

const paddingBottom = computed(() => {
  if (!props.verticalPadding) {
    return 0;
  }

  if (isBoolean(props.verticalPadding)) {
    return DEFAULT;
  } else if (isString(props.verticalPadding)) {
    return props.verticalPadding;
  } else {
    return !isUndefined(props.verticalPadding[1]) ? props.verticalPadding[1] : props.verticalPadding[0];
  }
});
</script>

<template>
  <div
    class="content-wrapper"
    :style="{
      '--content-wrapper-vertical-paddingTop': paddingTop === DEFAULT ? undefined : paddingTop,
      '--content-wrapper-vertical-paddingBottom': paddingBottom === DEFAULT ? undefined : paddingBottom,
    }"
  >
    <slot></slot>
  </div>
</template>

<style lang="scss" scoped>
.content-wrapper {
  max-width: var(--layout-content-max-width);
  padding-left: var(--layout-content-padding);
  padding-right: var(--layout-content-padding);
  margin: 0 auto;

  --content-wrapper-vertical-paddingTop: 72px;
  --content-wrapper-vertical-paddingBottom: 72px;
  padding-top: var(--content-wrapper-vertical-paddingTop);
  padding-bottom: var(--content-wrapper-vertical-paddingBottom);
}
</style>
