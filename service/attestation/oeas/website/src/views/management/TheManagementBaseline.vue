<script setup lang="ts">
import { ref } from 'vue';
import { OButton } from '@opensig/opendesign';

import ManagementCreateBaselineDialog from './components/ManagementCreateBaselineDialog.vue';
import imgEmpty from '@/assets/category/management/empty.png';

const showCreateDlg = ref(false);
</script>

<template>
  <div class="the-management-baseline">
    <!-- header -->
    <div class="header">
      <OButton size="large" type="primary" variant="solid" @click="showCreateDlg = true">新增基线</OButton>
      <span class="tip">上传同名文件，默认直接覆盖</span>
    </div>

    <!-- 空内容提示 -->
    <div class="no-content">
      <img class="empty" :src="imgEmpty" />
      <span class="tip">当前为内测版本，暂不支持查看基线，如需修改，可上传同名文件进行覆盖。</span>
    </div>

    <!-- 新增基线 -->
    <ManagementCreateBaselineDialog v-model:visible="showCreateDlg" />
  </div>
</template>

<style lang="scss" scoped>
.the-management-baseline {
  padding-top: 22px;

  .header {
    display: flex;
    align-items: center;

    .tip {
      margin-left: 16px;
      color: var(--o-color-info2);
      @include text1;
    }
  }

  .no-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding-top: 155px;
    color: var(--o-color-info2);
    text-align: center;
    @include text1;

    .empty {
      width: 220px;
    }

    .tip {
      margin-top: 16px;
    }
  }
}
</style>
