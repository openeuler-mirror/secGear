# OEAS WEB

## 基线管理

### 介绍说明

管理应用度量、硬件可信根等基线值。

### 可用功能

1. [新增基线](#新增基线)

### 功能说明

上传基线值，由远程证明服务端统一管理。

#### 新增基线

上传基线文件，文件类型(后缀)：\*.json。文件模板: [your_ref_name.json](./templates/your_ref_name.json)

## 证明策略管理

### 介绍说明

管理证明策略文件，证明策略中定义了证明报告的合法性检查方式。

### 可用功能

1. [新增证明策略](#新增证明策略)

### 功能说明

上传证明策略文件，由远程证明服务端统一管理。

#### 新增证明策略

上传证明策略文件，文件类型(后缀): \*.rego。策略编写与设置可见：[policy.md](./policy.md) 。文件模板：[your_policy_name.rego](./templates/your_policy_name.rego)

## 资源策略管理

### 介绍说明

管理资源策略，资源策略中定义了获取特定资源的合法性检查条件。

### 可用功能

1. [资源策略列表](#资源策略列表)
2. [新增资源策略](#新增资源策略)
3. [删除资源策略](#删除资源策略)
4. [查看资源策略内容](#查看资源策略内容)

### 功能说明

上传资源策略，由远程证明服务端统一管理。

#### 资源策略列表

显示已有资源策略至 Web 页面，提供查看策略内容、删除功能

#### 新增资源策略

上传资源策略文件，文件类型(后缀): \*.rego。策略编写与设置可见：[policy.md](./policy.md) 。文件模板：[your_res_policy_name.rego](./templates/your_res_policy_name.rego)

#### 删除资源策略

删除已有资源策略

#### 查看资源策略内容

查询指定资源策略内容

## 资源管理

### 介绍说明

管理用户上传的资源。

### 可用功能

1. [资源列表](#资源列表)
2. [新增资源](#新增资源)
3. [删除资源](#删除资源)
4. [修改资源](#修改资源)

### 功能说明

管理用户上传的资源，资源中保存密钥、账户密码等加密内容，并由远程证明服务端统一管理。

#### 资源列表

显示已有资源至 Web 页面，提供修改、删除功能

#### 新增资源

需填写资源名称、资源内容、需要绑定的资源策略名（即资源策略文件名，可选）

#### 删除资源

删除已有资源

#### 修改资源

修改资源内容与绑定的资源策略（可选），目前不支持已有资源的内容显示

## 常见报错

## FAQ

### 如何体验 OEAS 远程证明服务？

您需要申请 oeas 使用权限，才能使用 oeas-web。申请方式可见[oeas 主页](https://oeas.openeuler.org)

### 使用 OEAS Web 过程中发现问题？

可以将复现过程、报错内容提到仓库 issue，感谢您的反馈
