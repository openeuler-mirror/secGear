<script setup lang="ts">
import { OBadge, ODropdown, ODropdownItem, OIcon } from '@opensig/opendesign';

import IconUser from '~icons/app/icon-user.svg';
import { useUserInfo } from '@/stores/user';
import { getUserAuth, goToLogin, logout } from '@/shared/login';
import { onMounted } from 'vue';
import { ref } from 'vue';
import { getUserInfo, getUnreadMsgCount } from '@/api/api-user';

const userInfoStore = useUserInfo();

const onClickUser = () => {
  if (userInfoStore.loginStatus === 'NOT_LOGIN') {
    goToLogin();
  }
};

const jumpToUserZone = () => {
  window.open('https://www.openeuler.org/zh/workspace', '_blank');
};

const jumpToMsgCenter = () => {
  window.open(import.meta.env.VITE_MESSAGE_CENTER_URL, '_blank');
};

const unreadMsgCount = ref(0);

onMounted(async () => {
  const { token } = getUserAuth();
  if (token) {
    const { data: userInfo } = await getUserInfo();
    const giteeLoginName: string | undefined = (userInfo.identities as any[])?.find((item) => item.identity === 'gitee')?.login_name;
    const data = await getUnreadMsgCount(giteeLoginName);
    unreadMsgCount.value = Object.values(data).reduce((count, val) => count + val, 0);
  }
});
</script>

<template>
  <ODropdown v-if="userInfoStore.loginStatus === 'LOGINED'" trigger="hover">
    <div class="header-user">
      <template v-if="userInfoStore.guardAuthClient.photo">
        <OBadge v-if="unreadMsgCount" :value="unreadMsgCount" color="danger">
          <img :src="userInfoStore.guardAuthClient.photo" class="user-img" />
        </OBadge>
        <img v-else :src="userInfoStore.guardAuthClient.photo" class="user-img" />
      </template>
      <p v-if="userInfoStore.guardAuthClient.username" class="username" :title="userInfoStore.guardAuthClient.username">
        {{ userInfoStore.guardAuthClient.username }}
      </p>
    </div>
    <template #dropdown>
      <ODropdownItem @click="jumpToUserZone" class="header-user-dropdown-item" label="个人中心"> </ODropdownItem>
      <ODropdownItem @click="jumpToMsgCenter()" class="header-user-dropdown-item">
        <OBadge v-if="unreadMsgCount" :value="unreadMsgCount" color="danger"> 消息中心 </OBadge>
        <div v-else>消息中心</div>
      </ODropdownItem>
      <ODropdownItem @click="logout" class="header-user-dropdown-item" label="退出登录"> </ODropdownItem>
    </template>
  </ODropdown>
  <div v-else class="header-user">
    <OIcon @click="onClickUser">
      <IconUser class="icon" />
    </OIcon>
  </div>
</template>

<style lang="scss" scoped>
.header-user {
  display: flex;
  align-items: center;
  cursor: pointer;
  height: var(--layout-header-height);

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
