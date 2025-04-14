import { request, type AxiosResponse } from '@/shared/axios';

const xwwwForm = {
  req(url: string, data: Record<string, any>, method: string) {
    const params = new URLSearchParams();
    Object.entries(data).forEach(([k, v]) => {
      params.append(k, v);
    });
    return request({
      url,
      method: method,
      data: params,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
    }).then((res: AxiosResponse) => {
      return res.data;
    });
  },
  post(url: string, data: Record<string, any>) {
    return this.req(url, data, 'POST');
  },
  delete(url: string, data: Record<string, any>) {
    return this.req(url, data, 'DELETE');
  },
}

/**
 * 添加(修改)资源
 * @param {Record<string, string>} data 提交表单
 * @param {string} data.resource_name 资源名称
 * @param {string} data.policy_name 策略名称
 * @param {string} data.resource_content 资源内容
 */
export function addStorage(data: Record<string, string>) {
  const url = '/server/oeas-web/resource/storage';
  return xwwwForm.post(url, data);
}

/**
 * 删除资源
 * @param {Record<string, string>} params 提交参数
 * @param {string} params.resource_name 资源名称
 */
export function deleteStorage(params: Record<string, string>) {
  const url = '/server/oeas-web/resource/storage';

  return xwwwForm.delete(url, params)
}

/**
 * 获取资源清单
 */
export function getAllStorage() {
  const url = '/server/oeas-web/resource/storage/all';

  return request.get(url, { ignoreError: 500 }).then((res: AxiosResponse) => {
    return res.data;
  });
}

/**
 * 添加资源策略
 * @param {FormData} data 提交表单
 * @param {File} data.file 基线文件
 */
export function addResourcePolicy(data: FormData) {
  const url = '/server/oeas-web/resource/policy';

  return request
    .post(url, data, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
      },
    })
    .then((res: AxiosResponse) => {
      return res.data;
    });
}

/**
 * 删除资源策略
 * @param {Record<string, string>} params 提交参数
 * @param {string} params.policy_name 资源策略名称
 */
export function deleteResourcePolicy(params: { policy_name: string }) {
  const url = '/server/oeas-web/resource/policy';

  return xwwwForm.delete(url, params);
}

/**
 * 查询资源策略内容
 * @param {Record<string, string>} params 提交参数
 * @param {string} params.policy_name 资源策略名称
 */
export function getResourcePolicy(params: Record<string, string>) {
  const url = '/server/oeas-web/resource/policy';

  return request.get(url, { params }).then((res: AxiosResponse) => {
    return res.data;
  });
}

/**
 * 获取资源策略列表
 */
export function getAllResourcePolicy() {
  const url = '/server/oeas-web/resource/policy/all';

  return request.get(url, { ignoreError: 500 }).then((res: AxiosResponse) => {
    return res.data;
  });
}

/**
 * 添加基线
 * @param {FormData} data 提交表单
 * @param {File} data.file 基线文件
 */
export function addReference(data: FormData) {
  const url = '/server/oeas-web/reference';

  return request
    .post(url, data, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
      },
    })
    .then((res: AxiosResponse) => {
      return res.data;
    });
}

/**
 * 添加证明策略
 * @param {FormData} data 提交表单
 * @param {File} data.file 基线文件
 */
export function addPolicy(data: FormData) {
  const url = '/server/oeas-web/policy';

  return request
    .post(url, data, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
      },
    })
    .then((res: AxiosResponse) => {
      return res.data;
    });
}

/**
 * 获取证明策略
 * @param {Record<string, string>} params 请求参数
 * @param {string} params.policy_name 策略名称
 */
export function getPolicy(params: Record<string, string>) {
  const url = '/server/oeas-web/policy';

  return request.get(url, { params }).then((res: AxiosResponse) => {
    return res.data;
  });
}
