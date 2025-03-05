export default [
  {
    path: '/management',
    name: 'management',
    component: () => {
      return import('@/views/management/TheManagement.vue');
    },
    redirect() {
      return { name: 'baselineManagement' };
    },
    children: [
      {
        path: 'baseline',
        name: 'baselineManagement',
        component: () => {
          return import('@/views/management/TheManagementBaseline.vue');
        },
      },
      {
        path: 'policy',
        name: 'policyManagement',
        component: () => {
          return import('@/views/management/TheManagementPolicy.vue');
        },
      },
      {
        path: 'resource',
        name: 'resourceManagement',
        component: () => {
          return import('@/views/management/TheManagementResource.vue');
        },
      },
    ],
  },
];
