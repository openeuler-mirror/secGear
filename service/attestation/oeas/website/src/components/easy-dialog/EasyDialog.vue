<script setup lang="ts">
import { ODialog } from '@opensig/opendesign';
import { ref } from 'vue';
import { EasyDialogProps } from './types';

defineProps(EasyDialogProps);

const visible = ref(false);

const close = () => {
  visible.value = false;
};

const open = () => {
  visible.value = true;
};

defineExpose({
  close,
  open,
});
</script>

<template>
  <ODialog
    v-model:visible="visible"
    class="easy-dlg"
    :class="wrapClass"
    :actions="actions"
    :style="{
      '--dlg-width': width,
      '--headerAlign': headerAlign,
      '--contentAlign': contentAlign,
    }"
  >
    <template #header>{{ header }}</template>
    {{ content }}
  </ODialog>
</template>

<style lang="scss">
.easy-dlg {
  .o-dlg-header {
    text-align: var(--headerAlign);
  }

  .o-dlg-body {
    text-align: var(--contentAlign);
  }

  .o-dlg-footer {
    margin-top: 20px;
  }
}
</style>
