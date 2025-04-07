<script setup lang="ts">
import { reactive, ref } from 'vue';
import { useVModel } from '@vueuse/core';
import { ODialog, OButton, OForm, OFormItem, OIconAdd, OUpload, type UploadFileT, useMessage, isArray } from '@opensig/opendesign';

import { addReference } from '@/api/api-management';
import {
  MANAGEMENT_BASELINE_FILE_NAME_REGEXP,
  MANAGEMENT_BASELINE_FILE_SIZE,
  MANAGEMENT_BASELINE_FILE_SUFFIX,
  MANAGEMENT_BASELINE_FILE_TYPE,
} from '@/config/common';
import { watch } from 'vue';
import { computed } from 'vue';

//----------------------- 变量 --------------------------
const props = defineProps({
  visible: {
    type: Boolean,
    default: false,
  },
});

const emits = defineEmits(['update:visible']);
const message = useMessage();
const showDlg = useVModel(props, 'visible', emits);

//----------------------- 文件选择后校验 --------------------------
const requiredSelectRules = [
  {
    required: true,
    message: '请选择',
  },
];

const onAfterSelectBaselineFile = (files: FileList) => {
  const file = files[0];

  // 选择不是 json 的文件
  if (file.type !== MANAGEMENT_BASELINE_FILE_TYPE) {
    message.danger({
      content: '文件格式不正确，仅支持 json 文件',
    });

    return Promise.resolve([]);
  }

  // 文件大于 100 kb
  if (file.size > MANAGEMENT_BASELINE_FILE_SIZE) {
    message.danger({
      content: '文件大小不超过100KB',
    });

    return Promise.resolve([]);
  }

  // 文件名称仅支持字母和数字
  if (!MANAGEMENT_BASELINE_FILE_NAME_REGEXP.test(file.name.replace(MANAGEMENT_BASELINE_FILE_SUFFIX, ''))) {
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
  file: undefined as UploadFileT[] | undefined,
});

watch(
  () => showDlg.value,
  (val) => {
    if (!val) {
      formData.file = undefined;
    }
  },
);

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
    const postData = new FormData();
    postData.append('file', formData.file!![0].file!!);
    const res = await addReference(postData);
    showDlg.value = false;
    message.success({
      content: '新建成功',
    });
  } finally {
    loading.value = false;
  }
};
const selectedFile = computed(() =>  Array.isArray(formData.file) && formData.file.length > 0);
</script>

<template>
  <ODialog v-model:visible="showDlg" :style="{ '--dlg-width': '690px' }">
    <template #header>新增基线</template>

    <OForm ref="formRef" :model="formData" class="dlg-form" has-required label-justify="left" label-width="76px" @submit="submitForm">
      <OFormItem :class="['upload-form-item', selectedFile ? 'selected-file' : '']" label="基线内容" required field="file" :rules="requiredSelectRules">
        <OUpload v-model="formData.file" show-uploading-icon accept=".json" @after-select="onAfterSelectBaselineFile">
          <template #select-extra>
            <p>仅支持 json 类型文件，且文件最大不超过100KB</p>
            <p>文件名称至少1个字符，包含字母、数字或特殊符号（仅支持下划线_和横杠-）</p>
          </template>
          <OButton color="primary" size="large" variant="outline" :icon="OIconAdd">上传文件</OButton>
        </OUpload>
      </OFormItem>

      <div class="btn-form">
        <OButton size="large" type="submit" variant="solid" :loading="loading">确认</OButton>
        <OButton size="large" variant="outline" @click="showDlg = false">取消</OButton>
      </div>
    </OForm>
  </ODialog>
</template>

<style lang="scss" scoped>
.dlg-form {
  :deep(.o-upload-select-extra) {
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
