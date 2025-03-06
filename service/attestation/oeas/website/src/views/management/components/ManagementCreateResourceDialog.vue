<script setup lang="ts">
import { reactive, ref } from 'vue';
import { useVModel } from '@vueuse/core';
import { ODialog, OButton, OForm, OFormItem, OInput, OTextarea, useMessage, isArray } from '@opensig/opendesign';

import { MANAGEMENT_RESOURCE_NAME_MAX_LEN, MANAGEMENT_RESOURCE_NAME_MIN_LEN, MANAGEMENT_RESOURCE_NAME_REGEXP } from '@/config/common';
import { addStorage } from '@/api/api-management';

//----------------------- 变量 --------------------------
const props = defineProps({
  visible: {
    type: Boolean,
    default: false,
  },
  item: {
    type: Object,
    default: () => {},
  },
});

const emits = defineEmits(['update:visible', 'refresh']);
const message = useMessage();
const showDlg = useVModel(props, 'visible', emits);

//----------------------- 表单校验 --------------------------
// 资源名称校验
const resourceNameRules = [
  {
    required: true,
    message: '请输入资源名称',
  },
  {
    validator: (value: string) => {
      if (value.length > MANAGEMENT_RESOURCE_NAME_MAX_LEN || value.length < MANAGEMENT_RESOURCE_NAME_MIN_LEN) {
        return {
          type: 'danger',
          message: '最多输入30个字符',
        };
      } else if (!MANAGEMENT_RESOURCE_NAME_REGEXP.test(value)) {
        return {
          type: 'danger',
          message: '名称仅支持字母和数字',
        };
      }
    },
  },
];

// 资源名称校验
const resourceContentRules = [
  {
    required: true,
    message: '请输入资源内容',
  },
];

//----------------------- 表单提交 --------------------------
const loading = ref(false);
const formRef = ref<InstanceType<typeof OForm>>();
const formData = reactive({
  resource_name: '',
  policy_name: '',
  resource_content: '',
});

const submitForm = async () => {
  if (loading.value) {
    return;
  }

  const items = await formRef.value?.validate();
  if (isArray(items) && items.some((item) => item?.type === 'danger')) {
    return;
  }

  loading.value = true;
  try {
    const res = await addStorage(formData);
    emits('refresh');
    showDlg.value = false;
    message.success({
      content: '新建成功',
    });
  } finally {
    loading.value = false;
  }
};
</script>

<template>
  <ODialog v-model:visible="showDlg" :style="{ '--dlg-width': '930px' }">
    <template #header>新增策略</template>

    <OForm ref="formRef" class="dlg-form" has-required label-justify="left" label-width="76px" :model="formData" @submit="submitForm">
      <OFormItem label="资源名称" required field="resource_name" :rules="resourceNameRules">
        <OInput v-model="formData.resource_name" class="full-item" size="large" :max-length="30" :auto-size="false" placeholder="请输入需要绑定的策略ID" />
      </OFormItem>
      <OFormItem label="策略ID" field="polcy_id">
        <OInput v-model="formData.policy_name" class="full-item" size="large" placeholder="请输入需要绑定的策略ID" />
      </OFormItem>
      <OFormItem label="资源内容" required field="resource_content" :rules="resourceContentRules">
        <OTextarea v-model="formData.resource_content" class="full-item" size="large" :rows="18" :max-length="5000" placeholder="请输入资源内容" />
      </OFormItem>

      <div class="btn-form">
        <OButton size="large" type="submit" variant="solid" :loading="loading">确认</OButton>
        <OButton size="large" type="primary" variant="outline" @click="showDlg = false">取消</OButton>
      </div>
    </OForm>
  </ODialog>
</template>

<style lang="scss" scoped>
.dlg-form {
  color: var(--o-color-info1);

  .full-item {
    width: 100%;
  }

  .o-textarea {
    :deep(textarea) {
      resize: none !important;
    }
  }

  .btn-form {
    display: flex;
    justify-content: center;
    align-items: center;
    margin-top: 24px;

    .o-btn:not(:last-child) {
      margin-right: 16px;
    }
  }
}
</style>
