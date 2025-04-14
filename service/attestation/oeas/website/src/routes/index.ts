import { createRouter, createWebHistory } from 'vue-router';
import management from './management';
import { getUserAuth, goToLogin, isLogined } from '@/shared/login';
import { useUserInfo } from '@/stores/user';
import { checkUserPermission } from '@/api/api-user';

const routes = [
  ...management,
  {
    path: '/',
    redirect() {
      return { name: 'home' };
    },
  },
  {
    path: '/:path(.*)*',
    name: 'notFound',
    component: () => {
      return import('@/views/NotFound.vue');
    },
    meta: { title: '404' },
  },
];

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
});

router.beforeEach(async (to) => {
  const userInfoStore = useUserInfo();
  const { token } = getUserAuth();
  if (to.name === 'home') {
    if (token && !userInfoStore.guardAuthClient?.username) {
      const res = await isLogined();
      if (res) {
        const { hasPermission } = await checkUserPermission();
        userInfoStore.hasPermission = hasPermission;
      }
    }
    return true;
  }

  const cbLocation = location.origin + decodeURIComponent(to.fullPath);
  if (!token) {
    goToLogin(cbLocation);
    return false;
  }
  if (!userInfoStore.guardAuthClient?.username) {
    const res = await isLogined();
    if (res) {
      const { hasPermission } = await checkUserPermission();
      userInfoStore.hasPermission = hasPermission;
      return true;
    }
    goToLogin(cbLocation);
    return false;
  }
});

export default router;
