<script setup lang="ts">
import { computed, useSlots, type CSSProperties } from 'vue';

const slots = useSlots();

const props = defineProps({
  backgroundImage: {
    type: String,
    default: '',
  },
  backgroundColor: {
    type: String,
    default: '',
  },
  backgroundText: {
    type: String,
    default: '',
  },
  title: {
    type: String,
    default: '',
  },
  subtitle: {
    type: String,
    default: '',
  },
  illustration: {
    type: String,
    default: '',
  },
});

const rootStyle = computed(() => {
  const result: CSSProperties = {};
  if (props.backgroundColor) {
    result.backgroundColor = props.backgroundColor;
  }
  return result;
});
</script>

<template>
  <div class="banner-level2" :style="rootStyle">
    <img :src="props.backgroundImage" class="banner-bg" />
    <div class="wrap">
      <div class="banner-text">
        <h1 v-if="title" class="banner-title">{{ title }}</h1>
        <p v-if="subtitle" class="banner-subtitle">
          {{ subtitle }}
        </p>
        <div v-if="slots.default" class="banner-operation">
          <slot></slot>
        </div>
      </div>
      <div v-if="illustration" class="banner-illustration">
        <img :src="illustration" />
      </div>
    </div>
  </div>
</template>

<style lang="scss" scoped>
.banner-level2 {
  position: relative;
  width: 100%;
  background-size: cover;
  background-repeat: no-repeat;
  background-color: var(--o-color-control1-light);

  .banner-bg {
    position: absolute;
    height: 100%;
    width: 100%;
    object-fit: cover;
    user-select: none;
  }

  .wrap {
    position: relative;
    max-width: var(--layout-content-max-width);
    padding: 0 var(--layout-content-padding);
    margin: 0 auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 280px;

    @include respond-to('laptop') { 
      height: 260px;
    }

    @include respond-to('pad_h') {
      height: 220px;
    }

    .banner-text {
      display: flex;
      flex-direction: column;
      position: relative;
      max-width: 54%;

      .banner-text-bg {
        position: absolute;
        top: 0;
        color: var(--o-color-black);
        opacity: 0.14;
        font-weight: bold;
        user-select: none;
        @include display1;
      }

      .banner-title {
        position: relative;
        z-index: 1;
        color: var(--o-color-black);
        margin-bottom: 0;
        font-weight: 500;
        @include display1;
      }

      .banner-subtitle {
        position: relative;
        margin-top: 16px;
        color: var(--o-color-black);
        z-index: 1;
        @include h4;
      }

      .banner-operation {
        margin-top: 24px;
      }
    }

    .banner-illustration {
      position: absolute;
      top: 50%;
      transform: translateY(-50%);
      right: 44px;
      object-fit: fill;

      @include respond-to('laptop') {
        right: 16px;
      }

      img {
        user-select: none;
        max-height: 280px;

        @include respond-to('laptop') {
          max-height: 260px;
        }

        @include respond-to('pad_h') {
          max-height: 220px;
        }
      }
    }
  }
}
</style>
