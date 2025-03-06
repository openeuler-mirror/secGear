<script setup lang="ts">
import { ref } from 'vue';
import { OButton, OTable, OPagination, OLink, OPopover, useMessage } from '@opensig/opendesign';

import ManagementCreatePolicyDialog from './components/ManagementCreatePolicyDialog.vue';
import ManagementViewPolicyDialog from './components/ManagementViewPolicyDialog.vue';

import { COUNT_PER_PAGE } from '@/config/query';
import useDialog from '@/components/easy-dialog/use-dialog';
import { deleteResourcePolicy, getAllResourcePolicy } from '@/api/api-management';

const message = useMessage();
const showCreateDlg = ref(false);
const tbData = ref([
  {
    index: 0,
    name: '6666',
    type: 0,
  },
]);
const totals = ref(0);
const loading = ref(false);
const queryData = ref({
  page_num: 1,
  page_size: 10,
});

const columns = [
  { label: '序号', key: 'index', style: 'width: 10%' },
  { label: '策略名称', key: 'name', style: 'width: 20%' },
  { label: '策略类型', key: 'type', style: 'width: 45%' },
  { label: '操作', key: 'action', style: 'width: 25%' },
];

//----------------------- 获取列表 --------------------------
const queryList = async () => {
  if (loading.value) {
    return;
  }

  loading.value = true;
  try {
    const res = await getAllResourcePolicy();
    console.log(res);
  } finally {
    loading.value = false;
  }
}

//----------------------- 删除 --------------------------
const deleteData = async (name: string) => {
  try {
    const res = await deleteResourcePolicy({
      policy_name: name
    });

    message.success({
      content: '删除成功',
    });
  } catch{}
}

const deleteConfirm = (name: string) => {
  useDialog().open({
    header: '确认删除',
    content: '删除后内容不可恢复，确认删除？',
    headerAlign: 'center',
    contentAlign: 'center',
    width: '450px',
    actions: [
      {
        id: 'confirm',
        label: '确认',
        size: 'large',
        color: 'primary',
        variant: 'outline',
        onClick: () => {
          useDialog().close();
          deleteData(name);
        },
      },
      {
        id: 'cancel',
        label: '取消',
        size: 'large',
        color: 'primary',
        variant: 'solid',
        onClick: () => {
          useDialog().close();
        },
      },
    ],
  });
};

//----------------------- 预览策略 --------------------------
const previeItem = ref('');
const showViewDlg = ref(false);

const setViewDlgVisible = () => {
  showViewDlg.value = true;
};
</script>

<template>
  <div class="the-policy-baseline">
    <!-- header -->
    <div class="header">
      <OButton size="large" type="primary" variant="solid" :disabled="loading" @click="showCreateDlg = true">新增策略</OButton>
      <span class="tip">当前为内测版本，暂不支持证明策略的查看及删除，仅支持资源策略的查看及删除。如需修改，请上传同名文件进行覆盖</span>
    </div>

    <!-- 表格 -->
    <OTable class="policy-table" :columns="columns" :data="tbData" :loading="loading">
      <template #td_action="{ row }">
        <OLink color="primary" @click="setViewDlgVisible">预览</OLink>
        <OPopover position="top" trigger="hover">
          <template #target>
            <OLink disabled>修改</OLink>
          </template>
          <span>内测版暂不支持修改，可上传同名文件进行覆盖修改</span>
        </OPopover>
        <OLink color="danger" @click="deleteConfirm(row)">删除</OLink>
      </template>
    </OTable>
    <div v-if="tbData.length > 0 && totals > queryData.page_size && !loading" class="pagination">
      <OPagination :total="totals" :page="queryData.page_num" :page-size="queryData.page_size" :page-sizes="COUNT_PER_PAGE" :show-more="false" />
    </div>

    <!-- 新增策略 -->
    <ManagementCreatePolicyDialog v-model:visible="showCreateDlg" @refresh="queryList" />
    <!-- 预览策略 -->
    <ManagementViewPolicyDialog v-model:visible="showViewDlg" :name="previeItem" />
  </div>
</template>

<style lang="scss" scoped>
.the-policy-baseline {
  padding-top: 22px;

  .header {
    display: flex;
    align-items: center;

    .tip {
      margin-left: 16px;
      color: var(--o-color-info2);
      @include text1;
    }
  }

  .policy-table {
    margin-top: 24px;

    .o-link:not(:last-child) {
      margin-right: 32px;
    }
  }

  .pagination {
    margin-top: 40px;
    display: flex;
    align-items: center;
    justify-content: flex-end;
  }
}
</style>
