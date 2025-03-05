import type { DialogActionT } from '@opensig/opendesign/lib/dialog/types';
import type { ExtractPropTypes, PropType } from 'vue';

type EasyDialogAlignT = 'left' | 'center' | 'right';

export const EasyDialogProps = {
  wrapClass: {
    type: String,
  },
  header: {
    type: String,
    default: '',
  },
  headerAlign: {
    type: String as PropType<EasyDialogAlignT>,
    default: 'center',
  },
  content: {
    type: String,
    default: '',
  },
  contentAlign: {
    type: String as PropType<EasyDialogAlignT>,
    default: 'center',
  },
  width: {
    type: String,
    default: 'auto',
  },
  actions: {
    type: Array as PropType<DialogActionT[]>,
    default: () => [],
  },
};

export type EasyDialogPropsT = ExtractPropTypes<typeof EasyDialogProps>;
