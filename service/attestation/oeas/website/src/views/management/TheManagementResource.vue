<script setup lang="ts">
import { ref } from 'vue';
import { OButton, OTable, OPagination, OLink, OPopover, useMessage } from '@opensig/opendesign';

import ManagementCreateResourceDialog from './components/ManagementCreateResourceDialog.vue';

import { COUNT_PER_PAGE } from '@/config/query';
import useDialog from '@/components/easy-dialog/use-dialog';
import { deleteStorage, getAllStorage } from '@/api/api-management';

const message = useMessage();
const showCreateDlg = ref(false);
const tbData = ref([
  {
    index: 0,
    name: '6666',
    policy_id: '9999',
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
  { label: '资源名称', key: 'name', style: 'width: 20%' },
  { label: '策略ID', key: 'policy_id', style: 'width: 45%' },
  { label: '操作', key: 'action', style: 'width: 25%' },
];

//----------------------- 获取列表 --------------------------
const queryList = async () => {
  loading.value = true;
  try {
    const res = await getAllStorage();
    tbData.value = res.data;
  } finally {
    loading.value = false;
  }
}

queryList();

//----------------------- 删除 --------------------------
const deleteData = async (name: string) => {
  try {
    const res = await deleteStorage({
      resource_name: name
    });

    message.success({
      content: '删除成功',
    });
  } catch {}
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

//----------------------- 修改 --------------------------
const changeItem = ref();
const setCreateDlgVisible = (item?: Record<string, any>) => {
  changeItem.value = item;
  showCreateDlg.value = true;
}
</script>

<template>
  <div class="the-resource-baseline">
    <!-- header -->
    <div class="header">
      <OButton size="large" type="primary" variant="solid" @click="setCreateDlgVisible()">新增资源</OButton>
      <span class="tip">将需要托管的文本资源上传到远程证明服务</span>
    </div>

    <!-- 表格 -->
    <OTable class="resource-table" :columns="columns" :data="tbData" :loading="loading">
      <template #td_action="{ row }">
        <OPopover position="top" trigger="hover">
          <template #target>
            <OLink disabled>预览</OLink>
          </template>
          <span>内测版暂不支持预览</span>
        </OPopover>
        <OLink color="primary" @click="setCreateDlgVisible(row)">修改</OLink>
        <OLink color="danger" @click="deleteConfirm(row)">删除</OLink>
      </template>
    </OTable>
    <div v-if="tbData.length > 0 && totals > queryData.page_size && !loading" class="pagination">
      <OPagination :total="totals" :page="queryData.page_num" :page-size="queryData.page_size" :page-sizes="COUNT_PER_PAGE" :show-more="false" />
    </div>

    <!-- 新增资源 -->
    <ManagementCreateResourceDialog v-model:visible="showCreateDlg" />
  </div>
</template>

<style lang="scss" scoped>
.the-resource-baseline {
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

  .resource-table {
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
