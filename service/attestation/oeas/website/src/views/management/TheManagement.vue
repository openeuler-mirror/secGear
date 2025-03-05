<script setup lang="ts">
import { ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { OTab, OTabPane } from '@opensig/opendesign';

import BannerLevel2 from '@/components/BannerLevel2.vue';
import ContentWrapper from '@/components/ContentWrapper.vue';

import type { TabOptionT } from '@/@types/type-components';
import imgBanner from '@/assets/category/management/banner.jpg';
import imgIllustration from '@/assets/category/management/banner-illustration.png';

const route = useRoute();
const router = useRouter();
const activeTab = ref(route.name as string);
const tabs: TabOptionT[] = [
  {
    label: '基线管理',
    value: 'baselineManagement',
  },
  {
    label: '策略管理',
    value: 'policyManagement',
  },
  {
    label: '资源管理',
    value: 'resourceManagement',
  },
];

watch(activeTab, (val) => {
  router.push({
    name: val,
  });
});
</script>

<template>
  <div class="the-management">
    <BannerLevel2 :background-image="imgBanner" :illustration="imgIllustration" title="openEuler远程证明服务" />
    <ContentWrapper vertical-padding="40px">
      <OTab v-model="activeTab">
        <OTabPane v-for="item in tabs" :key="item.value" :value="item.value" :label="item.label" />
      </OTab>
      <RouterView />
    </ContentWrapper>
  </div>
</template>

<style lang="scss" scoped>
.the-management {
  :deep(.o-tab-navs) {
    justify-content: left;
  }
}
</style>
