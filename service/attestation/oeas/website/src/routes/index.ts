import { createRouter, createWebHistory } from 'vue-router';
import management from './management';

const routes = [
  ...management,
  {
    path: '/',
    redirect() {
      return { name: 'baselineManagement' };
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

export default router;
