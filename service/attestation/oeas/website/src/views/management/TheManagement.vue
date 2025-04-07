<script setup lang="ts">
import { ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { OTab, OTabPane } from '@opensig/opendesign';

import BannerLevel2 from '@/components/BannerLevel2.vue';
import ContentWrapper from '@/components/ContentWrapper.vue';

import type { TabOptionT } from '@/@types/type-components';
import imgBanner from '@/assets/category/management/banner.jpg';
import imgIllustration from '@/assets/category/management/banner-illustration.png';
import { computed } from 'vue';
import MailExample from '@/components/MailExample.vue';
import { storeToRefs } from 'pinia';
import { useUserInfo } from '@/stores/user';

const { hasPermission } = storeToRefs(useUserInfo());
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

const isHome = computed(() => {
  return route.name === 'home';
});

watch(isHome, (val, oldVal) => {
  if (val !== oldVal && !val) {
    activeTab.value = 'baselineManagement';
  }
});

const showDlg = ref(false);

const openDlg = () => {
  showDlg.value = true;
};
</script>

<template>
  <div class="the-management">
    <BannerLevel2 :background-image="imgBanner" :illustration="imgIllustration" title="openEuler远程证明服务" />
    <ContentWrapper :vertical-padding="isHome ? '32px' : '40px'">
      <template v-if="isHome || hasPermission">
        <OTab v-if="!isHome" v-model="activeTab">
          <OTabPane v-for="item in tabs" :key="item.value" :value="item.value" :label="item.label" />
        </OTab>
        <RouterView />
      </template>
      <div v-else class="no-permission">
        <img src="@/assets/category/illustrations/404.png" alt="no-permission" class="empty" />
        <p class="tip">没有权限</p>
        <p class="tip2">需要发送邮件到openEuler安全团队邮箱（<a href="mailto:openeuler-security@openeuler.org">openeuler-security@openeuler.org</a>）进行申请。</p>
        <a class="mail-example" @click="openDlg">查看邮件格式</a>
      </div>
    </ContentWrapper>
    <MailExample ref="mailExample" v-model:visible="showDlg" />
  </div>
</template>

<style lang="scss" scoped>
.the-management {
  :deep(.o-tab-navs) {
    justify-content: left;
  }
}

.content-wrapper {
  min-height: 925px;
}

.no-permission {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding-top: 120px;
  color: var(--o-color-info2);
  text-align: center;
  @include text1;

  .empty {
    width: 220px;
  }

  .tip {
    @include h4;
    margin-top: 24px;
    margin-bottom: 24px;
  }
  .tip2 {
    @include text1;
    color: var(--o-color-control2);
  }
  .mail-example {
    margin-top: 24px;
  }
}
</style>
