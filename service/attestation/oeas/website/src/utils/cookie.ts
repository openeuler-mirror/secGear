import { isString } from '@opensig/opendesign';

/**
 * 设置 cookie
 * @param {string} cname cookie 名
 * @param {string} cvalue cookie 值
 * @param {boolean} isDelete 是否为删除
 */
export function setCookie(cname: string, cvalue: string, isDelete?: boolean) {
  const deleteStr = isDelete ? 'max-age=0; ' : '';
  try {
    const domain = import.meta.env.VITE_COOKIE_DOMAIN;
    const expires = `${deleteStr}path=/; domain=${domain}`;
    document.cookie = `${cname}=${cvalue}; ${expires}`;
  } catch {}
}

/**
 * 获取 cookie
 * @param {string} cname cookie 名
 * @return 有返回对应的value，无返回空字符串
 */
export function getCookie(cname: string) {
  const name = `${cname}=`;
  const ca: any = isString(document.cookie) ? document.cookie.split(';') : [];

  for (let i = 0; i < ca.length; i++) {
    const c = ca[i].trim();
    if (c.indexOf(name) === 0) {
      return c.substring(name.length, c.length);
    }
  }

  return '';
}

/**
 * 删除 cookie
 * @param {string} cname cookie 名
 */
export function deleteCookie(cname: string) {
  setCookie(cname, 'null', true);
}
