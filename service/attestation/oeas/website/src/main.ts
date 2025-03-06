import { createApp } from 'vue';
import { createPinia } from 'pinia';

import '@/assets/style/base.scss';
import '@opensig/opendesign/es/index.css';
import '@/assets/style/theme/default-light.token.css';
import '@/assets/style/theme/index.scss';

import App from './App.vue';
import router from './routes';

const app = createApp(App);
app.use(createPinia());
app.use(router);
app.mount('#app');
