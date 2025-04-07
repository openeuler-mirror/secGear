<script setup lang="ts">
import { ODialog } from '@opensig/opendesign';
import { useVModel } from '@vueuse/core';

const props = defineProps({
  visible: {
    type: Boolean,
    default: false,
  },
});

const emit = defineEmits(['update:visible']);

const visibleVModel = useVModel(props, 'visible', emit);
</script>

<template>
  <ODialog class="mail-example-dlg" v-model:visible="visibleVModel">
    <p><span>邮件主题:</span>OEAS远程证明服务使用申请</p>
    <p>
      <span>邮件内容:</span><br />
      openEuler安全团队： <br />
      本人(公司、组织)有意愿参与openEuler社区OEAS服务测试，特此申请社区OEAS服务的使用权限。<br>
      社区用户名:xxx(注:请填写您的社区用户名)<br>
      社区账号:xxxxxxx(注:请填写您的社区账号登录使用的邮箱或手机号)
    </p>
  </ODialog>
</template>

<style lang="scss">
.mail-example-dlg {
  p {
    @include tip1;
    &:not(:first-child) {
      margin-top: 16px;
    }
    span {
      color: var(--o-color-info2);
    }
  }

  .o-dlg-body {
    @include respond-to('>laptop') {
      width: 690px;
    }
  }
}
</style>
