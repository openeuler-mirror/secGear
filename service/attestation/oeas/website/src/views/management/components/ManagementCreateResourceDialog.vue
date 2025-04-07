<script setup lang="ts">
import { reactive, ref } from 'vue';
import { useVModel } from '@vueuse/core';
import { ODialog, OButton, OForm, OFormItem, OInput, OTextarea, useMessage, isArray, type RulesT } from '@opensig/opendesign';

import { MANAGEMENT_RESOURCE_NAME_MAX_LEN, MANAGEMENT_RESOURCE_NAME_MIN_LEN, MANAGEMENT_RESOURCE_NAME_REGEXP } from '@/config/common';
import { addStorage } from '@/api/api-management';
import { watch } from 'vue';
import { computed } from 'vue';

//----------------------- 变量 --------------------------
const props = defineProps({
  visible: {
    type: Boolean,
    default: false,
  },
  isEdit: {
    type: Boolean,
    default: false,
  },
  name: {
    type: String,
    default: '',
  },
  item: {
    type: Object,
    default: () => {},
  },
});

const emits = defineEmits(['update:visible', 'refresh']);
const message = useMessage();
const showDlg = useVModel(props, 'visible', emits);
const title = computed(() => (props.isEdit ? '修改资源' : '新增资源'));

watch(showDlg, (val) => {
  if (val && props.name) {
    formData.resource_name = props.name;
  } else {
    Object.keys(formData).forEach((k) => {
      formData[k as keyof typeof formData] = '';
    });
  }
});
//----------------------- 表单校验 --------------------------
// 资源名称校验
const resourceNameRules: RulesT[] = [
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
    await addStorage(formData);
    setTimeout(() => emits('refresh'), 10);
    showDlg.value = false;
    message.success({
      content: props.isEdit ? '修改成功' : '新建成功',
    });
  } finally {
    loading.value = false;
  }
};
</script>

<template>
  <ODialog v-model:visible="showDlg" :style="{ '--dlg-width': '930px' }">
    <template #header>{{ title }}</template>

    <OForm ref="formRef" class="dlg-form" has-required label-justify="left" label-width="140px" :model="formData" @submit="submitForm">
      <OFormItem label="资源名称" class="align-center-form-item text-count-item" required field="resource_name" :rules="resourceNameRules">
        <OInput
          :disabled="isEdit"
          v-model="formData.resource_name"
          class="full-item"
          size="large"
          :max-length="30"
          :auto-size="false"
          :inputOnOutlimit="false"
          placeholder="请输入资源名称（至少1个字符，支持字母/数字/特殊符号，符号仅支持下划线_和横杠-）"
        />
        <div class="text-count">
          <span :class="{ danger: formData.resource_name.length > MANAGEMENT_RESOURCE_NAME_MAX_LEN }">{{ formData.resource_name.length }}</span
          >/{{ MANAGEMENT_RESOURCE_NAME_MAX_LEN }}
        </div>
      </OFormItem>
      <OFormItem label="资源策略名称" class="align-center-form-item" field="polcy_id">
        <OInput v-model="formData.policy_name" class="full-item" size="large" placeholder="请输入资源策略名称，如有多个策略请以英文逗号分隔" />
      </OFormItem>
      <OFormItem label="资源内容" required field="resource_content" :rules="resourceContentRules">
        <OTextarea v-model="formData.resource_content" class="full-item" size="large" :rows="12" :max-length="5000" placeholder="请输入资源内容" />
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
  --form-label-main-gap: 0;
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

  .text-count-item {
    :deep(.o-form-item-main-wrap) {
      position: relative;
    }

    .text-count {
      position: absolute;
      top: 0;
      right: 0;
      bottom: 0;
      display: flex;
      align-items: center;
      margin: 1px;
      padding: 0 12px;
      color: var(--o-color-info4);
      background-color: var(--o-color-fill2);
      border-radius: var(--o-radius-xs);
      @include tip2;

      .danger {
        color: var(--o-color-danger1);
      }
    }
  }
}
</style>
