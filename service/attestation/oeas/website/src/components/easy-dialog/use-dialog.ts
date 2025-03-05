import { createVNode, ref, render } from 'vue';
import EasyDialog from './EasyDialog.vue';
import type { EasyDialogPropsT } from './types';

const initDialog = (opt: EasyDialogPropsT) => {
  const el = document.querySelector('body');
  const vnode = createVNode(EasyDialog, Object.assign(opt || {}, { wrapper: el }));
  if (el) {
    render(vnode, el);
  }

  return vnode.component;
};

const instance = ref();

const useDialog = () => {
  const open = (option: EasyDialogPropsT) => {
    instance.value = initDialog(option);
    instance.value.exposed.open();
  };

  const close = () => {
    instance.value.exposed.close();
    instance.value = null;
  };

  return {
    open,
    close,
  };
};

export default useDialog;
