<script setup lang="ts">
import { OIcon } from '@opensig/opendesign';

import IconUser from '~icons/app/icon-user.svg';
import { useUserInfo } from '@/stores/user';
import { goToLogin } from '@/shared/login';

const userInfoStore = useUserInfo();

const onClickUser = () => {
  if (userInfoStore.loginStatus === 'NOT_LOGIN') {
    goToLogin();
  }
};
</script>

<template>
  <div class="header-user">
    <img v-if="userInfoStore.guardAuthClient.photo" :src="userInfoStore.guardAuthClient.photo" class="user-img" />
    <OIcon v-else @click="onClickUser">
      <IconUser class="icon" />
    </OIcon>
    <p v-if="userInfoStore.guardAuthClient.username" class="username" :title="userInfoStore.guardAuthClient.username">
      {{ userInfoStore.guardAuthClient.username }}
    </p>
  </div>
</template>

<style lang="scss" scoped>
.header-user {
  display: flex;
  align-items: center;
  cursor: pointer;

  .icon {
    width: 20px;
    height: 20px;
  }

  .user-img {
    width: 32px;
    height: 32px;
    border-radius: 50%;
  }

  .username {
    @include text-truncate(1);
    width: 72px;
    margin-left: 8px;
    color: var(--o-color-info1);
    @include text1;
  }
}
</style>
