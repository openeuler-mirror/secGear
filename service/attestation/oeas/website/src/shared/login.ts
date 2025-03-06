import { isObject } from '@opensig/opendesign';

import { getUserPermission } from '@/api/api-user';
import { useUserPermission } from '@/stores/user';
import { deleteCookie, getCookie } from '@/utils/cookie';
import type { UserPermissionT } from '@/@types/type-user';

const LOGIN_KEYS = {
  USER_TOKEN: '_U_T_',
  USER_INFO: '_U_I_',
};

/**
 * 存储 session 信息
 * @param {UserPermissionT} data 数据
 */
function setSessionInfo(data: UserPermissionT) {
  const { username, photo, aigcPrivacyAccepted } = data || {};
  if (username && photo) {
    sessionStorage.setItem(LOGIN_KEYS.USER_INFO, JSON.stringify({ username, photo, aigcPrivacyAccepted }));
  }
}

/**
 * 获取 session 存储信息
 * @returns {UserPermissionT} 返回 session 存储信息
 */
function getSessionInfo() {
  let username = '';
  let photo = '';
  let aigcPrivacyAccepted = '';

  try {
    const info = sessionStorage.getItem(LOGIN_KEYS.USER_INFO);
    if (info) {
      const obj = JSON.parse(info) || {};
      username = obj.username || '';
      photo = obj.photo || '';
      aigcPrivacyAccepted = obj.aigcPrivacyAccepted || '';
    }
  } catch (error) {}

  return {
    username,
    photo,
    aigcPrivacyAccepted,
  } as UserPermissionT;
}

/**
 * 移除 session 信息
 */
function removeSessionInfo() {
  sessionStorage.removeItem(LOGIN_KEYS.USER_INFO);
}

/**
 * 跳转登录页面
 */
export function goToLogin() {
  const origin = import.meta.env.VITE_LOGIN_ORIGIN;
  location.href = `${origin}/login?redirect_uri=${encodeURIComponent(location.href)}`;
}

/**
 * 清除用户登录信息
 */
export function clearUserAuth() {
  const { clearGuardAuthClient } = useUserPermission();
  clearGuardAuthClient();
  deleteCookie(LOGIN_KEYS.USER_TOKEN);
  removeSessionInfo();
}

/**
 * 获取用户 token
 */
export function getUserAuth() {
  const token = getCookie(LOGIN_KEYS.USER_TOKEN) || '';

  // 不存在 token
  if (!token) {
    clearUserAuth();
  }

  return {
    token,
  };
}

/**
 * 判断是否登录
 */
export async function isLogined() {
  const { setGuardAuthClient, setLoginStatus } = useUserPermission();
  const { token } = getUserAuth();

  // 不存在 token
  if (!token) {
    return false;
  }

  try {
    const res = await getUserPermission({ community: 'openeuler' });
    if (isObject(res.data)) {
      setGuardAuthClient(res.data);
      setSessionInfo(res.data);
      setLoginStatus('LOGINED');
      return true;
    } else {
      clearUserAuth();
    }
  } catch {
    clearUserAuth();
  }

  return false;
}
