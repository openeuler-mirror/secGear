<script setup lang="ts">
import { reactive, ref } from 'vue';
import { useVModel } from '@vueuse/core';
import { ODialog, OButton, OForm, OFormItem, OIconAdd, OUpload, ORadioGroup, ORadio, type UploadFileT, useMessage, isArray } from '@opensig/opendesign';

import { POLICY_TYPE } from '@/config/management';
import { MANAGEMENT_POLICY_FILE_NAME_REGEXP, MANAGEMENT_POLICY_FILE_SIZE, MANAGEMENT_POLICY_FILE_SUFFIX } from '@/config/common';
import { addPolicy, addResourcePolicy } from '@/api/api-management';

//----------------------- 变量 --------------------------
const props = defineProps({
  visible: {
    type: Boolean,
    default: false,
  },
});

const emits = defineEmits(['update:visible', 'refresh']);
const message = useMessage();
const showDlg = useVModel(props, 'visible', emits);

//----------------------- 表单校验 --------------------------
// 策略类型校验
const requiredSelectRules = [
  {
    required: true,
    message: '请选择',
  },
];

// 文件选择后校验
const onAfterSelectBaselineFile = (files: FileList) => {
  const file = files[0];
  console.log(file);

  // 选择不是 repo 的文件
  if (!file.name.endsWith(MANAGEMENT_POLICY_FILE_SUFFIX)) {
    message.danger({
      content: '文件格式不正确，仅支持 repo 文件',
    });

    return Promise.resolve([]);
  }

  // 文件大于 100 kb
  if (file.size > MANAGEMENT_POLICY_FILE_SIZE) {
    message.danger({
      content: '文件大小不超过100KB',
    });

    return Promise.resolve([]);
  }

  // 文件名称仅支持字母和数字
  if (!MANAGEMENT_POLICY_FILE_NAME_REGEXP.test(file.name.replace(MANAGEMENT_POLICY_FILE_SUFFIX, ''))) {
    message.danger({
      content: '文件名称仅支持字母和数字',
    });

    return Promise.resolve([]);
  }

  return Promise.resolve([
    {
      id: file.name,
      name: file.name,
      file: file,
    },
  ]);
};

//----------------------- 表单提交 --------------------------
const loading = ref(false);
const formRef = ref<InstanceType<typeof OForm>>();
const formData = reactive({
  type: 0,
  file: undefined as UploadFileT[] | undefined,
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
    const request = formData.type === 0 ? addPolicy : addResourcePolicy;
    const postData = new FormData();
    postData.append('file', formData.file!![0].file!!);
    const res = await request(postData);
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
  <ODialog v-model:visible="showDlg" :style="{ '--dlg-width': '690px' }">
    <template #header>新增策略</template>

    <OForm ref="formRef" :model="formData" class="dlg-form" has-required label-justify="left" label-width="76px" @submit="submitForm">
      <OFormItem label="策略类型" required field="type" :rules="requiredSelectRules">
        <ORadioGroup v-model="formData.type" direction="v">
          <ORadio v-for="option in POLICY_TYPE.values()" :key="option.value" :value="option.value">
            <div class="radio-title">{{ option.label }}</div>
            <div class="radio-desc">{{ option.desc }}</div>
          </ORadio>
        </ORadioGroup>
      </OFormItem>
      <OFormItem label="策略内容" required field="file" :rules="requiredSelectRules">
        <OUpload v-model="formData.file" show-uploading-icon accept=".repo" @after-select="onAfterSelectBaselineFile">
          <template #select-extra>仅支持 repo 类型文件，上传文件名称仅支持字母和数字，且文件最大不超过100KB</template>
          <OButton color="primary" size="large" variant="outline" :icon="OIconAdd">上传文件</OButton>
        </OUpload>
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

  :deep(.o-upload-select-extra) {
    color: var(--o-color-info3);
    @include tip1;
  }

  :deep(.o-radio-wrap) {
    align-items: start;
  }

  .radio-title {
    font-weight: 500;
    @include text1;
  }

  .radio-desc {
    margin-top: 4px;
    color: var(--o-color-info3);
    @include tip1;
  }

  .btn-form {
    display: flex;
    justify-content: center;
    align-items: center;
    margin-top: 104px;

    .o-btn:not(:last-child) {
      margin-right: 16px;
    }
  }
}
</style>
