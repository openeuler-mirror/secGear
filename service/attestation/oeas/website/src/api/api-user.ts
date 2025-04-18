import { request } from '@/shared/axios';
import type { AxiosResponse } from '@/shared/axios';

import { getUserAuth } from '@/shared/login';

/**
 * 获取授权的相关回调链接
 * @param {string} params.community 社区名
 */
export function getUserPermission(params: { community: string }) {
  const url = '/api-omapi/oneid/user/permission';

  return request
    .get(url, {
      params,
      global: true,
    })
    .then((res: AxiosResponse) => {
      return res.data;
    });
}

/**
 * 获取用户的授权信息
 */
export function checkUserPermission() {
  const url = '/api-omapi/oneid/user/checkPermission';

  return request
    .post(
      url,
      {
        resource: 'secgear',
        actions: ['access'],
      },
      { showError: false }
    )
    .then((res: AxiosResponse) => {
      return res.data.data as { hasPermission: boolean };
    })
    .catch(() => ({ hasPermission: false }));
}

/**
 * 查询用户信息
 */
export function getUserInfo() {
  const url = '/api-omapi/oneid/personal/center/user?community=openeuler';
  const { token } = getUserAuth();

  return request
    .get(url, {
      headers: {
        token,
      },
    })
    .then((res: AxiosResponse) => {
      return res.data;
    });
}

/**
 * 获取消息中心未读消息数量
 */
export function getUnreadMsgCount(giteeLoginName?: string) {
  return request
    .get<{ count: Record<string, number> }>('/api-message/inner/count_new', {
      params: { gitee_user_name: giteeLoginName },
      showError: false,
    })
    .then((res) => res.data.count)
    .catch(() => ({}));
}
