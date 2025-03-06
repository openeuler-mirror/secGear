import { ref } from 'vue';
import { defineStore } from 'pinia';
import { isObject } from '@opensig/opendesign';
import type { UserPermissionT } from '@/@types/type-user';

export type LoginStatus = 'NOT_LOGIN' | 'LOGINING' | 'LOGINED';

export const useUserPermission = defineStore('login', () => {
  // 登录信息
  const guardAuthClient = ref<UserPermissionT>({
    aigcPrivacyAccepted: '',
    email: '',
    photo: '',
    username: '',
  });

  // 设置登录信息
  const setGuardAuthClient = (data: UserPermissionT) => {
    if (isObject(data)) {
      Object.keys(guardAuthClient.value).forEach((key) => {
        guardAuthClient.value[key as keyof UserPermissionT] = data[key as keyof UserPermissionT] || '';
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
  };
});
