<script setup lang="ts">
import { ref, computed, watch, type PropType } from 'vue';

import { linksData, linksData2, quickNav, friendshipLinks } from '@/config/footer';

import { ODivider } from '@opensig/opendesign';
import ContentWrapper from './ContentWrapper.vue';

import LogoFooter from '@/assets/category/footer/footer-logo2.png';
import LogoFooter1 from '@/assets/category/footer/footer-logo1.png';
import LogoAtom from '@/assets/category/footer/atom-logo.png';

// 公众号、小助手
import CodeTitleXzs from '@/assets/category/footer/img-xzs.png';
import CodeTitleGzh from '@/assets/category/footer/img-gzh.png';
import CodeImgXzs from '@/assets/category/footer/code-xzs.png';
import CodeImgZgz from '@/assets/category/footer/code-zgz.jpg';

const props = defineProps({
  lang: {
    type: String as PropType<'zh' | 'en'>,
    default: 'zh',
  },
  target: {
    type: String,
    default: '_blank',
  },
});

const locale = ref('zh');

// 公众号、小助手
const footerCodeList = [
  {
    img: CodeTitleGzh,
    code: CodeImgZgz,
    label: 'openEuler小助手',
  },
  {
    img: CodeTitleXzs,
    code: CodeImgXzs,
    label: 'openEuler公众号',
  },
];

//-------------底部媒体 hover 改变图片 src-----------------
const currentHoverId = ref('');

const currentMediaData = computed(() => {
  return linksData[props.lang];
});

const handleMouseEnter = (id: string) => {
  currentHoverId.value = id;
};
const handleMouseLeave = () => {
  currentHoverId.value = '';
};

const getImgSrc = (id: string) => {
  const logo = currentMediaData.value.find((item) => item.id === id);
  if (logo && currentHoverId.value === id) {
    return logo.logo.hover;
  } else if (logo) {
    return logo.logo.normal;
  }
};

watch(
  () => props.lang,
  (val) => {
    locale.value = val as 'zh' | 'en';
  },
  { immediate: true }
);
</script>

<template>
  <div id="tour_footer" class="footer">
    <ContentWrapper :pc-top="0" :mobile-top="0">
      <div class="atom">
        <p class="atom-text">openEuler 是由开放原子开源基金会（OpenAtom Foundation）孵化及运营的开源项目</p>
        <a href="https://openatom.cn" target="_blank">
          <img :src="LogoAtom" class="atom-logo" alt="" />
        </a>
      </div>
      <ODivider
        :style="{
          '--o-divider-bd-color': 'rgba(229, 229, 229, 0.12)',
          '--o-divider-gap': '16px',
        }"
      />
    </ContentWrapper>
    <div class="footer-content">
      <ContentWrapper :pc-top="0" :mobile-top="0">
        <div class="quick-nav">
          <div v-for="category in quickNav[lang]" class="category">
            <div class="category-title">
              {{ category.title }}
            </div>
            <ul class="navs">
              <li v-for="nav in category.list" class="nav">
                <a :href="nav.link" target="_blank" rel="noopener noreferrer">{{ nav.title }}</a>
              </li>
            </ul>
          </div>
        </div>
        <div class="friendship-link">
          <div class="friendship-link-title">友情链接</div>
          <div class="friendship-link-box">
            <a v-for="link in friendshipLinks[lang]" class="friendship-link-item" :href="link.link" :key="link.link" target="_blank">{{ link.title }}</a>
          </div>
        </div>
        <div class="inner">
          <div class="footer-logo">
            <img class="show-pc" :src="LogoFooter" alt="" />
            <img class="show-mo" :src="LogoFooter1" alt="" />
            <p>
              <a class="email" href="mailto:contact@openeuler.io" target="_blank"> contact@openeuler.io </a>
            </p>
          </div>
          <div class="footer-option">
            <div class="footer-option-item">
              <template v-for="(link, index) in linksData2[lang]" :key="link.URL">
                <a :target="target" :href="link.URL" class="link">{{ link.NAME }}</a>
                <ODivider
                  v-if="index !== linksData2[lang].length - 1"
                  :style="{
                    '--o-divider-bd-color': 'var(--o-color-white)',
                    '--o-divider-label-gap': '0 8px',
                  }"
                  direction="v"
                />
              </template>
            </div>
            <p class="copyright">版权所有 © {{ new Date().getFullYear() }} openEuler 保留一切权利</p>
            <p class="license">
              <span>遵循</span>
              木兰宽松许可证第2版（MulanPSL2）
            </p>
          </div>
          <div class="footer-right">
            <div v-if="lang === 'zh'" class="code-box">
              <div v-for="(item, index) in footerCodeList" :key="index" class="code-pop">
                <img :src="item.img" class="code-img" alt="" />
                <div class="code-layer">
                  <img :src="item.code" alt="" />
                  <p class="txt">{{ item.label }}</p>
                </div>
              </div>
            </div>
            <div class="footer-links" :class="{ iszh: lang === 'zh' }">
              <a
                v-for="item in currentMediaData"
                :key="item.path"
                :href="item.path"
                @mouseenter="handleMouseEnter(item.id)"
                @mouseleave="handleMouseLeave()"
                class="links-logo"
                target="_blank"
              >
                <img :style="{ height: `${item.height}px` }" :src="getImgSrc(item.id)" alt="" />
              </a>
            </div>
          </div>
        </div>
      </ContentWrapper>
    </div>
  </div>
</template>

<style lang="scss" scoped>
$color: #fff;
.o-divider {
  @include tip2;
}

.footer {
  overflow: hidden;
  background: #121214;

  &.is-doc {
    margin-left: 300px;

    @media (max-width: 1100px) {
      margin-left: 0;
    }
  }

  :deep(.app-content) {
    padding-bottom: 0;
  }

  .atom {
    text-align: center;
    margin-top: 24px;
    position: relative;

    .atom-text {
      color: $color;
      @include h4;
    }

    .atom-logo {
      height: 32px;
      margin-top: 12px;

      @include respond-to('<=pad_v') {
        margin-top: 16px;
        height: 30px;
      }
    }
  }

  .footer-content {
    background: url('@/assets/category/footer/footer-bg.png') no-repeat bottom center;
    @include tip1;

    @include respond-to('<=pad_v') {
      background: url('@/assets/category/footer/footer-bg-mo.png') no-repeat bottom center;
    }

    .quick-nav {
      margin: 16px auto 0;
      display: flex;
      justify-content: space-between;
      max-width: 1140px;

      @include respond-to('<=pad_v') {
        display: none;
      }

      .category {
        .category-title {
          color: var(--o-color-white);
          @include h4;
        }

        .navs {
          display: flex;
          flex-direction: column;

          .nav {
            margin-top: 8px;
            @include tip1;

            a {
              color: rgba(255, 255, 255, 0.6);

              @include hover {
                color: rgba(255, 255, 255, 1);
              }
            }
          }

          .nav:first-child {
            margin-top: 10px;
          }
        }
      }
    }

    .friendship-link {
      margin-top: 16px;
      padding-bottom: 12px;
      display: flex;
      border-bottom: 1px solid rgba(229, 229, 229, 0.12);
      @include tip2;

      @include respond-to('<=pad_v') {
        flex-direction: column;
        padding-bottom: 16px;

        .friendship-link-box {
          margin-top: 12px;
        }
      }

      .friendship-link-title {
        color: var(--o-color-white);
        margin-right: 38px;

        @include respond-to('<=pad') {
          margin-right: 24px;
        }
      }

      .friendship-link-item {
        white-space: nowrap;
        color: rgba(255, 255, 255, 0.6);

        &:not(:last-of-type) {
          margin-right: 24px;

          @include respond-to('<=pad') {
            margin-right: 12px;
          }
        }

        @include hover {
          color: rgba(255, 255, 255, 1);
        }
      }
    }

    .inner {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      padding: 8px 0 32px;
      position: relative;

      @include respond-to('<=pad_v') {
        margin: 0 auto;
        max-width: 240px;
        padding: 12px 0 24px;
        flex-direction: column;
        justify-content: space-between;
        align-items: center;
      }
    }
  }

  .footer-logo {
    flex: 1;

    img {
      height: 46px;
    }

    .show-pc {
      display: block;
    }

    .show-mo {
      display: none;
    }

    @include respond-to('<=pad_v') {
      text-align: center;
      margin: 16px 0;

      .show-pc {
        display: none;
      }

      .show-mo {
        display: inline-block;
        height: 20px;
      }

      p {
        margin-top: 4px;
      }
    }
  }

  .copyright {
    margin-top: 6px;
    color: rgba(255, 255, 255, 0.6);

    @include respond-to('<=pad_v') {
      margin-top: 4px;
    }
  }

  .license {
    color: $color;
    margin-top: 6px;

    span {
      color: rgba(255, 255, 255, 0.6);
    }

    @include respond-to('<=pad_v') {
      margin-top: 4px;
    }
  }

  .footer-option {
    text-align: center;

    @include tip1;
    .link {
      color: $color;
      display: inline-block;
    }

    .footer-option-item {
      display: flex;
      align-items: center;
    }

    @include respond-to('<=pad_v') {
      order: -1;
    }
  }

  .footer-right {
    flex: 1;

    .code-box {
      display: flex;
      justify-content: right;
      gap: 16px;

      .code-pop {
        cursor: pointer;
        position: relative;
        height: 20px;
        display: block;

        > img {
          height: 100%;
          object-fit: cover;
        }

        .code-layer {
          position: absolute;
          top: -105px;
          left: -32px;
          z-index: 99;
          display: none;
          background: #fff;
          padding: 6px;

          img {
            width: 78px;
            height: 78px;
          }

          .txt {
            margin-top: 8px;
            color: $color;
            display: none;
          }

          &::after {
            border: 10px solid transparent;
            content: '';
            border-top-color: #fff;
            position: absolute;
            bottom: -20px;
            left: 50%;
            transform: translateX(-50%);
            display: block;
          }

          @include respond-to('<=pad_v') {
            display: block;
            position: initial;
            background: none;
            padding: 0;
            text-align: center;

            &::after {
              display: none !important;
            }

            .txt {
              display: block;
            }
          }
        }

        @include hover {
          .code-layer {
            display: block;
          }
        }

        @include respond-to('pad_h') {
          height: 18px;
        }

        @include respond-to('<=pad_v') {
          height: auto;

          > img {
            display: none;
          }
        }
      }

      @include respond-to('<=pad_v') {
        justify-content: space-between;
      }
    }

    .footer-links {
      display: flex;
      justify-content: right;
      align-items: center;
      gap: 12px;
      margin-left: 24px;

      .links-logo {
        display: flex;
        align-items: center;
        height: 26px;
        padding: 0 14px;
        background-color: #2b2b2f;
        border-radius: var(--o-radius-xs);
        @include respond-to('pad_h') {
          height: 26px;
          padding: 0 8px;
        }
        @include respond-to('<=pad_v') {
          height: 26px;
          padding: 0 8px;
        }
        .logo {
          object-fit: cover;
        }
      }
      @include respond-to('pad_h') {
        margin-left: 32px;
      }
      @include respond-to('<=pad_v') {
        justify-content: center;
        display: flex;
        text-align: center;
        margin-left: 0;
      }
      &.iszh {
        margin-top: 12px;
        gap: 12px 8px;
        .links-logo {
          padding: 0 9px;
          height: 20px;
        }
        @include respond-to('<=pad') {
          display: flex;
          flex-wrap: wrap;
          text-align: center;
        }
      }
    }

    p {
      color: $color;
      margin-top: var(--o-spacing-h8);
    }
  }

  .email {
    color: $color;
  }
}

[lang='en'] {
  .footer {
    .footer-content {
      .inner {
        @include respond-to('<=pad_v') {
          margin: 0 auto;
          max-width: fit-content;
          padding: 14px 0 24px;
          flex-direction: column;
          justify-content: space-between;
          align-items: center;
        }
      }
    }
  }
}
</style>
