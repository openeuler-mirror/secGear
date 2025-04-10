<script setup lang="ts">
import { OIcon, OLink } from '@opensig/opendesign';
import IconOutlink from '~icons/app/icon-outlink.svg';
import IconFeature from '~icons/app/icon-home-feature.svg';
import IconInfo from '~icons/app/icon-info.svg';
import { ref } from 'vue';
import MailExample from '@/components/MailExample.vue';

const showDlg = ref(false);

const openDlg = () => {
  showDlg.value = true;
};
</script>

<template>
  <div class="section service-desc">
    <h2>服务介绍</h2>
    <div class="card">
      <img src="@/assets/category/management/home-desc.png" alt="service-desc" />
      <div class="desc">
        <p>
          openEuler Attestation Service
          (OEAS)是欧拉社区推出的基于开源机密计算项目secGear远程证明统一框架的机密计算远程证明服务。致力于提供简单、易用的机密计算远程证明服务，兼容多TEE平台实现统一远程证明流程，推动机密计算生态发展。
          <a href="https://www.openeuler.org/zh/blog/20250409-secGear/20250409-secGear.html" target="_blank" rel="noopener noreferrer">secGear远程证明统一框架介绍</a>
        </p>
        <p>
          OEAS服务完全开源，源代码在Gitee社区的openeuler仓库下，以下是仓库地址：
          <OLink
            class="out-link"
            color="primary"
            href="https://gitee.com/openeuler/secGear/tree/master"
            hover-underline
            target="_blank"
            rel="noopener noreferrer"
          >
            secGear代码仓库
            <OIcon class="icon"><IconOutlink /></OIcon>
          </OLink>
          <OLink
            class="out-link"
            color="primary"
            href="https://gitee.com/openeuler/secGear/tree/master/service/attestation/oeas"
            hover-underline
            target="_blank"
            rel="noopener noreferrer"
          >
            OEAS代码仓库
            <OIcon class="icon"><IconOutlink /></OIcon>
          </OLink>
        </p>
      </div>
    </div>
  </div>

  <div class="section feature-support">
    <h2>功能支持</h2>
    <div class="card">
      <div class="content">
        <div class="left">
          <p class="title">
            <IconFeature />
            OEAS管理
          </p>
          <p class="desc">目前OEAS-Web测试版可使用功能有:</p>
          <ul>
            <li><strong>基线管理：</strong>新增基线</li>
            <li><strong>证明策略管理：</strong>新增证明策略</li>
            <li><strong>资源策略管理：</strong>新增资源策略、查看资源策略内容、删除资源策略</li>
            <li><strong>资源管理：</strong>添加托管资源、修改托管资源、删除托管资源</li>
          </ul>
          <p class="info">
            具体说明可见<a
              href="https://gitee.com/openeuler/secGear/blob/master/service/attestation/oeas/docs/oeas_web.md"
              target="_blank"
              rel="noopener noreferrer"
              >OEAS WEB</a
            >文档
          </p>
        </div>
        <div class="right">
          <p class="title">
            <IconFeature />
            OEAS-API
          </p>
          <p class="desc">
            目前OEAS服务开放的API有<code>/challenge</code><code>/attestation</code><code>/resource/storage</code>用于实现远程证明的验证。具体可参考
            <a href="https://gitee.com/openeuler/secGear/blob/master/service/attestation/oeas/docs/oeas_api.md" target="_blank" rel="noopener noreferrer"
              >OEAS API文档</a
            >，文档同时提供了一键调用API实现远程证明的脚本，欢迎使用。
          </p>
          <p class="desc">您可通过openEuler社区“个人中心”>“私人令牌”获取所需的私人令牌，用以调用API。</p>
        </div>
      </div>
      <div class="bottom-info">
        <IconInfo />
        <p>
          目前OEAS仍处于测试阶段，若您有意愿参与或体验OEAS服务，需要发送邮件到openEuler安全团队邮箱（<a href="mailto:openeuler-security@openeuler.org"
            >openeuler-security@openeuler.org</a
          >）进行申请。
          <a class="mail-example" @click="openDlg">查看邮件格式</a>
        </p>
      </div>
    </div>
  </div>

  <MailExample v-model:visible="showDlg" />
</template>

<style scoped lang="scss">
.section {
  display: flex;
  flex-direction: column;
  align-items: center;
  h2 {
    @include display3;
    font-weight: normal;
    margin-bottom: 32px;
  }

  .card {
    padding: 8px;
    display: flex;
    align-items: center;
    width: 100%;
    background-color: white;
  }

  &:nth-child(2) {
    margin-top: 72px;
  }
}

.service-desc {
  .card {
    padding-right: 32px;
    border-radius: 4px;
    img {
      border-radius: 4px;
    }
  }
  .desc {
    margin-left: 40px;

    p {
      color: var(--o-color-info2);
      &:not(:first-child) {
        margin-top: 28px;
      }
    }

    .out-link:not(:last-child) {
      margin-right: 28px;
    }

    .out-link {
      padding: 0;
    }

    :deep(.o-link-label) {
      display: flex;
      align-items: center;
      gap: 8px;

      svg {
        width: 16px;
        margin-right: 4px;
        fill: currentColor;
      }
    }
  }
}

.feature-support {
  .card {
    background-image: url('@/assets/category/management/home-feature-bg.png');
    background-size: 100% 100%;
    background-color: #ebecff;
    background-repeat: no-repeat;
    padding-left: 32px;
    padding-right: 32px;
    padding-top: 32px;
    padding-bottom: 40px;
    display: block;

    .content {
      display: flex;
      flex-direction: row;
      justify-content: space-between;
      align-items: flex-start;
      padding-bottom: 32px;
      border-bottom: 1px solid rgba($color: #000000, $alpha: 0.1);

      @mixin common {
        flex: 1;
        .title {
          @include h3;
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .desc {
          margin-top: 16px;
          margin-left: 44px;
          color: var(--o-color-info2);
        }
      }

      .left {
        @include common;
        border-right: 1px solid rgba($color: #000000, $alpha: 0.1);
        .info {
          margin-left: 44px;
          margin-top: 16px;
        }
        ul {
          margin-top: 16px;
          margin-left: 30px;
          li {
            &:not(:last-child) {
              margin-bottom: 12px;
            }
            &::before {
              content: '\002022';
              color: var(--o-color-info2);
              margin-right: 8px;
            }
            color: var(--o-color-info2);
            strong {
              color: var(--o-color-black);
            }
          }
        }
      }

      .right {
        @include common;
        margin-left: 32px;
        code {
          background-color: var(--o-color-white);
          margin-right: 2px;
          margin-left: 2px;
          padding: 0 4px;
          &:not(:first-child) {
            margin-left: 8px;
          }
        }
      }
    }

    .bottom-info {
      display: flex;
      align-items: center;
      height: 24px;
      margin-top: 40px;

      p {
        margin-left: 12px;

        .mail-example {
          margin-left: 12px;
        }
      }
    }
  }
}
</style>
