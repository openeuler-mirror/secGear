// 中文媒体链接
import LogoBilibili from '@/assets/category/footer/bilibili.png';
import LogoToutiao from '@/assets/category/footer/toutiao.png';
import LogoJuejin from '@/assets/category/footer/juejin.png';
import LogoOschina from '@/assets/category/footer/oschina.png';
import LogoCsdn from '@/assets/category/footer/csdn.png';

// 英文媒体链接
import LogoRedditSquare from '@/assets/category/footer/reddit-square.png';
import LogoLinkedin from '@/assets/category/footer/linkdin.png';
import LogoYoutube from '@/assets/category/footer/youtube.png';
import LogoTwitter from '@/assets/category/footer/x.png';

// 中文媒体链接
import LogoBilibiliHover from '@/assets/category/footer/bilibili_hover.png';
import LogoToutiaoHover from '@/assets/category/footer/toutiao_hover.png';
import LogoJuejinHover from '@/assets/category/footer/juejin_hover.png';
import LogoOschinaHover from '@/assets/category/footer/oschina_hover.png';
import LogoCsdnHover from '@/assets/category/footer/csdn_hover.png';

// 英文媒体链接
import LogoRedditSquareHover from '@/assets/category/footer/reddit-square_hover.png';
import LogoLinkedinHover from '@/assets/category/footer/linkdin_hover.png';
import LogoYoutubeHover from '@/assets/category/footer/youtube_hover.png';
import LogoTwitterHover from '@/assets/category/footer/x_hover.png';

// 媒体链接
export const linksData = {
  zh: [
    {
      path: 'https://my.oschina.net/openeuler',
      logo: {
        normal: LogoOschina,
        hover: LogoOschinaHover,
      },
      id: 'oschina',
      height: 14,
    },
    {
      path: 'https://blog.csdn.net/openEuler_?spm=1000.2115.3001.5343',
      logo: {
        normal: LogoCsdn,
        hover: LogoCsdnHover,
      },
      id: 'csdn',
      height: 11,
    },
    {
      path: 'https://juejin.cn/user/3183782863845454',
      logo: {
        normal: LogoJuejin,
        hover: LogoJuejinHover,
      },
      id: 'juejin',
      height: 11,
    },
    {
      path: 'https://space.bilibili.com/527064077/channel/series',
      logo: {
        normal: LogoBilibili,
        hover: LogoBilibiliHover,
      },
      id: 'bilibili',
      height: 13,
    },
    {
      path: 'https://www.toutiao.com/c/user/token/MS4wLjABAAAAZivzVkJzMyQ44GzmX1i_ON0bgxL3E8ybHC-P9HMqZiqUgpYVnjCjynDt-SebKN7r',
      logo: {
        normal: LogoToutiao,
        hover: LogoToutiaoHover,
      },
      id: 'toutiao',
      height: 13,
    },
  ],
  en: [
    {
      path: 'https://www.linkedin.com/company/openeuler',
      logo: {
        normal: LogoLinkedin,
        hover: LogoLinkedinHover,
      },
      id: 'linkedin',
      height: 16,
    },
    {
      path: 'https://x.com/openEuler',
      logo: {
        normal: LogoTwitter,
        hover: LogoTwitterHover,
      },
      id: 'twitter',
      height: 16,
    },
    {
      path: 'https://www.youtube.com/channel/UCPzSqXqCgmJmdIicbY7GAeA',
      logo: {
        normal: LogoYoutube,
        hover: LogoYoutubeHover,
      },
      id: 'youtube',
      height: 12,
    },
    {
      path: 'https://www.reddit.com/r/openEuler/',
      logo: {
        normal: LogoRedditSquare,
        hover: LogoRedditSquareHover,
      },
      id: 'reddit-square',
      height: 16,
    },
  ],
};

// 隐私链接
export const linksData2 = {
  zh: [
    {
      NAME: '品牌',
      URL: 'https://www.openeuler.org/zh/other/brand/',
    },
    {
      NAME: '隐私政策',
      URL: 'https://www.openeuler.org/zh/other/privacy/',
    },
    {
      NAME: '法律声明',
      URL: 'https://www.openeuler.org/zh/other/legal/',
    },
    {
      NAME: '关于cookies',
      URL: 'https://www.openeuler.org/zh/other/cookies/',
    },
  ],
  en: [
    {
      NAME: 'Trademark',
      URL: 'https://www.openeuler.org/en/other/brand/',
    },
    {
      NAME: 'Privacy Policy',
      URL: 'https://www.openeuler.org/en/other/privacy/',
    },
    {
      NAME: 'Legal Notice',
      URL: 'https://www.openeuler.org/en/other/legal/',
    },
    {
      NAME: 'About Cookies',
      URL: 'https://www.openeuler.org/en/other/cookies/',
    },
  ],
};

// 底部导航数据
export const quickNav = {
  zh: [
    {
      title: '关于openEuler',
      list: [
        {
          title: '成员单位',
          link: '/zh/community/member/',
        },
        {
          title: '组织架构',
          link: '/zh/community/organization/',
        },
        {
          title: '社区章程',
          link: '/zh/community/charter/',
        },
        {
          title: '贡献看板',
          link: 'https://datastat.openeuler.org/zh/overview',
        },
        {
          title: '社区介绍',
          link: '/whitepaper/openEuler%20%E5%BC%80%E6%BA%90%E7%A4%BE%E5%8C%BA%E4%BB%8B%E7%BB%8D.pdf',
        },
      ],
    },
    {
      title: '新闻与资讯',
      list: [
        {
          title: '新闻',
          link: '/zh/interaction/news-list/',
        },
        {
          title: '博客',
          link: '/zh/interaction/blog-list/',
        },
        {
          title: '白皮书',
          link: '/zh/showcase/technical-white-paper/',
        },
      ],
    },
    {
      title: '获取与下载',
      list: [
        {
          title: '获取openEuler操作系统',
          link: '/zh/download/#get-openeuler',
        },
        {
          title: '最新社区发行版',
          link: '/zh/download/',
        },
        {
          title: '商业发行版',
          link: '/zh/download/commercial-release/',
        },
        {
          title: '软件中心',
          link: 'https://easysoftware.openeuler.org/zh',
        },
      ],
    },
    {
      title: '支持与服务',
      list: [
        {
          title: '文档',
          link: 'https://docs.openeuler.org/zh/',
        },
        {
          title: 'FAQ',
          link: 'https://www.openeuler.org/zh/faq/',
        },
        {
          title: '联系我们',
          link: '/zh/contact-us/',
        },
        // {
        //   title: '反馈问题',
        //   link: '',
        // },
      ],
    },
    {
      title: '互动与交流',
      list: [
        {
          title: '邮件列表',
          link: '/zh/community/mailing-list/',
        },
        {
          title: '活动',
          link: '/zh/interaction/event-list/',
        },
        {
          title: '论坛',
          link: 'https://forum.openeuler.org/',
        },
      ],
    },
    {
      title: '贡献与成长',
      list: [
        {
          title: 'SIG中心',
          link: '/zh/sig/sig-list/',
        },
        {
          title: '贡献攻略',
          link: '/zh/community/contribution/',
        },
        {
          title: '课程中心',
          link: '/zh/learn/mooc/',
        },
      ],
    },
  ],
  en: [
    {
      title: 'About openEuler',
      list: [
        {
          title: 'Members',
          link: '/en/community/member/',
        },
        {
          title: 'Governance',
          link: '/en/community/organization/',
        },
        {
          title: 'Code of Conduct',
          link: '/en/community/charter/',
        },
        {
          title: 'Statistics',
          link: 'https://datastat.openeuler.org/en/overview',
        },
      ],
    },
    {
      title: 'News & Blogs',
      list: [
        {
          title: 'News',
          link: '/en/interaction/news-list/',
        },
        {
          title: 'Blogs',
          link: '/en/interaction/blog-list/',
        },
        {
          title: 'White Papers',
          link: '/en/showcase/technical-white-paper/',
        },
      ],
    },
    {
      title: 'Access',
      list: [
        {
          title: 'openEuler Is Everywhere',
          link: '/en/download/#get-openeuler',
        },
        {
          title: 'Latest Community Releases',
          link: '/en/download/',
        },
        {
          title: 'Commercial Releases',
          link: '/en/download/commercial-release/',
        },
        // {
        //   title: '软件中心',
        //   link: 'https://easysoftware.openeuler.org/en',
        // },
      ],
    },
    {
      title: 'Services & Resources',
      list: [
        {
          title: 'Documentation',
          link: 'https://docs.openeuler.org/en/',
        },
        {
          title: 'FAQ',
          link: 'https://www.openeuler.org/en/faq/',
        },
        {
          title: 'Contact Us',
          link: '/en/contact-us/',
        },
        // {
        //   title: '反馈问题',
        //   link: '',
        // },
      ],
    },
    {
      title: 'Communicate',
      list: [
        {
          title: 'Mailing Lists',
          link: '/en/community/mailing-list/',
        },
        {
          title: 'Activities',
          link: '/en/interaction/event-list/',
        },
        {
          title: 'Forum',
          link: 'https://forum.openeuler.org/',
        },
      ],
    },
    {
      title: 'Contribute',
      list: [
        {
          title: 'SIGs',
          link: '/en/sig/sig-list/',
        },
        {
          title: 'Contribution Guide',
          link: '/en/community/contribution/',
        },
        {
          title: 'Training',
          link: '/zh/learn/mooc/',
        },
      ],
    },
  ],
};

export const friendshipLinks = {
  zh: [
    {
      link: 'http://www.mulanos.cn/',
      title: '木兰开源社区',
    },
    {
      link: 'https://www.hikunpeng.com/zh/',
      title: '鲲鹏社区',
    },
    {
      link: 'http://ic-openlabs.huawei.com/chat/#/',
      title: '鲲鹏小智',
    },
    {
      link: 'https://pcl.ac.cn/',
      title: '鹏城实验室',
    },
    {
      link: 'https://www.infoq.cn/?utm_source=openeuler&utm_medium=youlian',
      title: 'infoQ',
    },
    {
      link: 'https://kaiyuanshe.cn/',
      title: '开源社',
    },
    {
      link: 'http://www.vulab.com.cn/',
      title: '中科微澜',
    },
    {
      link: 'https://www.authing.cn/',
      title: 'Authing',
    },
    {
      link: 'https://www.opengauss.org/zh/',
      title: 'openGauss',
    },
    {
      link: 'https://www.mindspore.cn/',
      title: '昇思MindSpore',
    },
    {
      link: 'http://www.ebaina.com/',
      title: 'Ebaina',
    },
  ],
  en: [
    {
      link: 'https://www.infoq.cn/?utm_source=openeuler&utm_medium=youlian',
      title: 'infoQ',
    },
    {
      link: 'https://www.authing.cn/',
      title: 'Authing',
    },
    {
      link: 'https://www.opengauss.org/en/',
      title: 'openGauss',
    },
    {
      link: 'https://www.mindspore.cn/',
      title: 'MindSpore',
    },
    {
      link: 'http://www.ebaina.com/',
      title: 'Ebaina',
    },
  ],
};
