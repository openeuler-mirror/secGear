import type { AxiosStatic } from 'axios';

/**
 * 设置 axios 实例的配置项
 * @param {axios} axios实例
 * @param {config} 自定义配置对象，可覆盖掉默认的自定义配置
 */
export default (axios: AxiosStatic, config = {}) => {
  const defaultConfig = {
    timeout: 20000,
    headers: {
      'Content-Type': 'application/json;charset=UTF-8',
    },
  };
  Object.assign(axios.defaults, defaultConfig, config);
  return axios;
};
