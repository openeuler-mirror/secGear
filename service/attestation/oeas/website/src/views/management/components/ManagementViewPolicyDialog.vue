<script setup lang="ts">
import { useVModel } from '@vueuse/core';
import { ODialog, OForm, OFormItem, OScroller } from '@opensig/opendesign';
import { ref, watch } from 'vue';
import { getResourcePolicy } from '@/api/api-management';

//----------------------- 变量 --------------------------
const props = defineProps({
  visible: {
    type: Boolean,
    default: false,
  },
  name: {
    type: String,
    default: '',
  },
});

const emits = defineEmits(['update:visible']);
const showDlg = useVModel(props, 'visible', emits);
const loading = ref(false);
const content = ref('');

const queryContent = async () => {
  loading.value = false;
  try {
    const res = await getResourcePolicy({
      policy_name: props.name,
    });

    content.value = res;
  } finally {
    loading.value = false;
  }
};

watch(
  () => props.visible,
  (val) => {
    if (val) {
      queryContent();
    } else {
      content.value = '';
    }
  }
);
</script>

<template>
  <ODialog v-model:visible="showDlg" class="" :style="{ '--dlg-width': '930px' }">
    <template #header>查看资源策略</template>
    <OForm ref="formRef" class="view-policy-form dlg-form" has-required label-justify="left" label-width="110px">
      <OFormItem label="资源策略名称">
        <div class="name">{{ name }}</div>
      </OFormItem>
      <OFormItem label="资源策略内容">
        <OScroller class="content-wrap" show-type="hover">
          <div class="content">{{ content }}</div>
        </OScroller>
      </OFormItem>
    </OForm>
  </ODialog>
</template>

<style lang="scss">
.view-policy-form {
  .o-form-item-label {
    line-height: 40px;
  }
}
</style>

<style lang="scss" scoped>
.dlg-form {
  color: var(--o-color-info1);
  @include text1;

  :deep(.o-scrollbar-y) {
    margin: 0;
    --scrollbar-height: 100%;
    --scrollbar-track-bg-color: transparent;
  }

  .name,
  .content-wrap {
    width: 100%;
    border-radius: var(--o-radius-xs);
    background-color: var(--o-color-fill1);
  }

  .name {
    height: 40px;
    padding: 8px 12px;
  }

  .content-wrap {
    height: 388px;
    overflow-y: auto;
  }

  .content {
    padding: 8px 12px;
    white-space: pre-wrap;
  }
}
</style>
