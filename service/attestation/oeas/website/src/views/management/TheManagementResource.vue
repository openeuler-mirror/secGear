<script setup lang="ts">
import { computed, ref } from 'vue';
import { OButton, OTable, OPagination, OLink, OPopover, useMessage, TabVariantTypes } from '@opensig/opendesign';

import ManagementCreateResourceDialog from './components/ManagementCreateResourceDialog.vue';

import { COUNT_PER_PAGE } from '@/config/query';
import useDialog from '@/components/easy-dialog/use-dialog';
import { deleteStorage, getAllStorage } from '@/api/api-management';

const message = useMessage();
const showCreateDlg = ref(false);
const tbData = ref<any[]>([]);
const totals = ref(0);
const loading = ref(false);
const queryData = ref({
  page_num: 1,
  page_size: 10,
});

const columns = [
  { label: '序号', key: 'index', style: 'width: 10%' },
  { label: '资源名称', key: 'name', style: 'width: 65%' },
  // { label: '策略ID', key: 'policy_id', style: 'width: 45%' },
  { label: '操作', key: 'action', style: 'width: 25%' },
];

//----------------------- 获取列表 --------------------------
const isEmpty = ref(false);
const queryList = async () => {
  loading.value = true;
  try {
    const res = await getAllStorage();
    if (!Array.isArray(res) || res.length === 0) {
      tbData.value = [];
      isEmpty.value = true;
      return;
    }
    if (Array.isArray(res)) {
      isEmpty.value = false;
      tbData.value = res.map((item, index) => {
        return {
          index: index + 1,
          name: item.split('/')[1].split('.')[0],
        };
      });
    }
  } catch (error) {
    tbData.value = [];
    isEmpty.value = true;
  } finally {
    loading.value = false;
  }
};

queryList();

//----------------------- 删除 --------------------------
const deleteData = async (name: string) => {
  try {
    const res = await deleteStorage({
      resource_name: name,
    });

    message.success({
      content: '删除成功',
    });
  } catch {}
};

const deleteConfirm = (row: any) => {
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
          deleteData(row.name).then(() => setTimeout(queryList, 10));
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
const editName = ref('');
const isEdit = ref(false);

const setCreateDlgVisible = (item?: Record<string, any>) => {
  changeItem.value = item;
  if (item?.name) {
    editName.value = item.name;
    isEdit.value = true;
    showCreateDlg.value = true;
    return; 
  }
  isEdit.value = false;
  editName.value = '';
  showCreateDlg.value = true;
};

const tableClasses = computed(() => {
  const res = ['resource-table'];
  if (isEmpty.value) {
    res.push('hidden');
  }
  if (loading.value) {
    res.push('loading');
  }
  return res;
});
</script>

<template>
  <div class="the-resource-baseline">
    <!-- header -->
    <div class="header">
      <OButton size="large" :disabled="loading" type="primary" variant="solid" @click="setCreateDlgVisible()">新增资源</OButton>
      <span class="tip">将需要托管的文本资源上传到远程证明服务</span>
    </div>

    <!-- 表格 -->
    <div class="resource-table-wrap">
      <OTable :class="tableClasses" :columns="columns" :data="tbData" :loading="loading" >
        <template #td_action="{ row }">
          <OPopover position="top" trigger="hover">
            <template #target>
              <OLink disabled>预览</OLink>
            </template>
            <span>内测版暂不支持预览</span>
          </OPopover>
          <OLink color="primary" @click="setCreateDlgVisible(row)">修改</OLink>
          <OLink color="danger" @click="deleteConfirm(row as any)">删除</OLink>
        </template>
      </OTable>
      <div class="not-found" v-if="isEmpty">
        <img src="@/assets/category/management/not-found.png" alt="not-found" />
        <p>您暂未新建资源</p>
      </div>
    </div>
    <div v-if="tbData.length > 0 && totals > queryData.page_size && !loading" class="pagination">
      <OPagination :total="totals" :page="queryData.page_num" :page-size="queryData.page_size" :page-sizes="COUNT_PER_PAGE" :show-more="false" />
    </div>

    <!-- 新增资源 -->
    <ManagementCreateResourceDialog @refresh="queryList" :is-edit="isEdit" :name="editName" v-model:visible="showCreateDlg" />
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
  .resource-table-wrap {
    margin-top: 24px;
    position: relative;

    .resource-table {
      min-height: calc(11 * var(--table-cell-height));
      &.hidden {
        z-index: -1;
      }
      .o-link:not(:last-child) {
        margin-right: 32px;
      }
      &.loading {
        :deep(.o-table-wrap) {
          min-height: calc(11 * var(--table-cell-height));
        }
      }
    }

    .not-found {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      display: flex;
      flex-direction: column;
      align-items: center;

      p {
        margin-top: 16px;
        font-size: var(--o-font_size-text1);
        color: var(--o-color-info2);
      }
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
