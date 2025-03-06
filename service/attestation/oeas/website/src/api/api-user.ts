import { request } from '@/shared/axios';
import type { AxiosResponse } from '@/shared/axios';

import { getUserAuth } from '@/shared/login';

/**
 * 获取授权的相关回调链接
 * @param {string} params.community 社区名
 */
export function getUserPermission(params: { community: string }) {
  const url = '/api-omapi/oneid/user/permission';
  const { token } = getUserAuth();

  return request
    .get(url, {
      params,
      global: true,
      headers: {
        token,
      },
    })
    .then((res: AxiosResponse) => {
      return res.data;
    });
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
