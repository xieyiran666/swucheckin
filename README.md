# SWU 自动签到

西南大学钉钉签到自动脚本，每天 21:10 自动执行，**无需服务器、无需开电脑、无视位置限制**。

## 使用说明（零基础版）

### 第一步：注册 GitHub 账号

1. 打开 [github.com](https://github.com)
2. 点右上角 **Sign up**，用邮箱注册
3. 验证邮箱后登录

### 第二步：复制本项目

1. 打开本项目页面
2. 点右上角 **Fork** 按钮
3. 等几秒，你会得到一个属于自己的仓库副本

### 第三步：填写学号和密码

1. 进入你 Fork 的仓库
2. 点顶部 **Settings** 标签
3. 左侧菜单点 **Secrets and variables** → **Actions**
4. 点绿色 **New repository secret** 按钮
5. 分别添加两个 Secret：

| Name | 值 |
|------|-----|
| `SWU_USERNAME` | 你的学号 |
| `SWU_PASSWORD` | 你的密码 |

- 先点 **New repository secret**，Name 填 `SWU_USERNAME`，Secret 填学号，点 **Add secret**
- 再点 **New repository secret**，Name 填 `SWU_PASSWORD`，Secret 填密码，点 **Add secret**

### 第四步：测试运行

1. 点顶部 **Actions** 标签
2. 点左侧 **SWU Check-in**
3. 点右侧 **Run workflow** → 绿色 **Run workflow** 按钮
4. 刷新页面，看到正在运行的任务
5. 点进去看运行日志，确认签到成功

### 第五步：完成

以后每天北京时间 **21:10** 自动执行签到，无需任何操作。

---

## 多人使用

每个人各自 Fork 一份到自己的 GitHub 账号，填入自己的学号密码即可，互相独立。

## 暂停 / 恢复

- **暂停**：进入 Actions 页面 → 点 **...** → **Disable workflow**
- **恢复**：同样位置点 **Enable workflow**
- 寒暑假关掉，开学再打开

## 常见问题

**签到失败怎么办？**
- 进入 Actions 页面查看运行日志
- 返回码含义：
  - `0` = 今天没有签到任务
  - `1` = 签到成功
  - `2` = 今天已经签过了
  - `3` = 账号密码错误
  - `4` = 网络超时（会自动重试）
  - `5` = 请假中

**密码改了怎么办？**
- 进入 Settings → Secrets and variables → Actions
- 找到 `SWU_PASSWORD`，点右边的编辑图标，更新后保存

**需要收费吗？**
- 完全免费。GitHub Actions 对公开仓库不限时长。

**安全吗？**
- Secrets 是加密存储的，GitHub 不会明文展示
- 只有你自己能看到和管理
- 建议使用强密码保护 GitHub 账号

**验证码识别失败？**
- 脚本使用 OCR 自动识别 4 位验证码
- 偶尔失败会在日志中显示，可以手动重新触发一次
