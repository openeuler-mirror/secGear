import { ref } from 'vue';
import { defineStore } from 'pinia';
import { isObject } from '@opensig/opendesign';
import type { UserInfoT } from '@/@types/type-user';

export type LoginStatus = 'NOT_LOGIN' | 'LOGINING' | 'LOGINED';

export const useUserInfo = defineStore('login', () => {
  // 登录信息
  const guardAuthClient = ref<UserInfoT>({
    aigcPrivacyAccepted: '',
    email: '',
    photo: '',
    username: '',
  });
  const hasPermission = ref(false);

  // 设置登录信息
  const setGuardAuthClient = (data: UserInfoT) => {
    if (isObject(data)) {
      Object.keys(guardAuthClient.value).forEach((key) => {
        guardAuthClient.value[key as keyof UserInfoT] = data[key as keyof UserInfoT] || '';
      });
    } else {
      clearGuardAuthClient();
    }
  };

  // 清除登录状态
  const clearGuardAuthClient = () => {
    setLoginStatus('NOT_LOGIN');
    setGuardAuthClient({
      aigcPrivacyAccepted: '',
      email: '',
      photo: '',
      username: '',
    });
  };

  // 登录状态
  const loginStatus = ref<LoginStatus>('NOT_LOGIN');
  const setLoginStatus = (status: LoginStatus) => {
    loginStatus.value = status;
  };

  return {
    guardAuthClient,
    setGuardAuthClient,
    clearGuardAuthClient,
    loginStatus,
    setLoginStatus,
    hasPermission,
  };
});
