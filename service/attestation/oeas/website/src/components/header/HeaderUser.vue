<script setup lang="ts">
import { OIcon } from '@opensig/opendesign';

import IconUser from '~icons/app/icon-user.svg';

import { goToLogin, isLogined } from '@/shared/login';
import { useUserPermission } from '@/stores/user';

const userPermissionInfo = useUserPermission();

async function getUserInfo() {
  const result = await isLogined();
  if (!result) {
    //goToLogin();
  }
}

getUserInfo();
</script>

<template>
  <div class="header-user">
    <img v-if="userPermissionInfo.guardAuthClient.photo" :src="userPermissionInfo.guardAuthClient.photo" class="user-img" />
    <OIcon v-else class="icon">
      <IconUser />
    </OIcon>
    <p class="username" :title="userPermissionInfo.guardAuthClient.username">{{ userPermissionInfo.guardAuthClient.username }}</p>
  </div>
</template>

<style lang="scss" scoped>
.header-user {
  display: flex;
  align-items: center;
  cursor: pointer;

  .icon {
    font-size: 16px;
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
