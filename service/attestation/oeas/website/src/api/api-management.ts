import { request, type AxiosResponse } from '@/shared/axios';

/**
 * 添加(修改)资源
 * @param {Record<string, string>} data 提交表单
 * @param {string} data.resource_name 资源名称
 * @param {string} data.policy_name 策略名称
 * @param {string} data.resource_content 资源内容
 */
export function addStorage(data: Record<string, string>) {
  const url = '/server/resource/storage';

  return request.post(url, data).then((res: AxiosResponse) => {
    return res.data;
  });
}

/**
 * 删除资源
 * @param {Record<string, string>} params 提交参数
 * @param {string} params.resource_name 资源名称
 */
export function deleteStorage(params: Record<string, string>) {
  const url = '/server/resource/storage';

  return request.delete(url, { params }).then((res: AxiosResponse) => {
    return res.data;
  });
}

/**
 * 获取资源清单
 */
export function getAllStorage() {
  const url = '/server/resource/storage/all';

  return request.get(url).then((res: AxiosResponse) => {
    return res.data;
  });
}

/**
 * 添加资源策略
 * @param {FormData} data 提交表单
 * @param {File} data.file 基线文件
 */
export function addResourcePolicy(data: FormData) {
  const url = '/server/resource/policy';

  return request.post(url, data).then((res: AxiosResponse) => {
    return res.data;
  });
}

/**
 * 删除资源策略
 * @param {Record<string, string>} params 提交参数
 * @param {string} params.policy_name 资源策略名称
 */
export function deleteResourcePolicy(params: Record<string, string>) {
  const url = '/server/resource/policy';

  return request.delete(url, { params }).then((res: AxiosResponse) => {
    return res.data;
  });
}

/**
 * 查询资源策略内容
 * @param {Record<string, string>} params 提交参数
 * @param {string} params.policy_name 资源策略名称
 */
export function getResourcePolicy(params: Record<string, string>) {
  const url = '/server/resource/policy';

  return request.get(url, { params }).then((res: AxiosResponse) => {
    return res.data;
  });
}

/**
 * 获取资源策略列表
 */
export function getAllResourcePolicy() {
  const url = '/server/resource/policy/all';

  return request.get(url).then((res: AxiosResponse) => {
    return res.data;
  });
}

/**
 * 添加基线
 * @param {FormData} data 提交表单
 * @param {File} data.file 基线文件
 */
export function addReference(data: FormData) {
  const url = '/server/reference';

  return request.post(url, data).then((res: AxiosResponse) => {
    return res.data;
  });
}

/**
 * 添加证明策略
 * @param {FormData} data 提交表单
 * @param {File} data.file 基线文件
 */
export function addPolicy(data: FormData) {
  const url = '/server/policy';

  return request.post(url, data).then((res: AxiosResponse) => {
    return res.data;
  });
}

/**
 * 获取证明策略
 * @param {Record<string, string>} params 请求参数
 * @param {string} params.policy_name 策略名称
 */
export function getPolicy(params: Record<string, string>) {
  const url = '/server/policy';

  return request
    .get(url, { params })
    .then((res: AxiosResponse) => {
      return res.data;
    });
}
