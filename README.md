# ⚡️ Cloudflare Workers 节点管理系统 (CF-Node-Manager)

[![Deployment](https://img.shields.io/badge/Deploy%20to-Cloudflare%20Workers-orange?logo=cloudflare&style=flat-square)](https://workers.cloudflare.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)]()
[![Version](https://img.shields.io/badge/Version-9.9-green?style=flat-square)]()

一个运行在 Cloudflare Workers 上的轻量级、无服务器（Serverless）IP 节点管理与订阅生成系统。

它能够帮你收集、清洗、去重和管理来自不同来源（订阅链接、API、本地文件、Telegram）的 IP 节点，并生成带智能备注的聚合订阅文件。**无需购买服务器，完全利用 Cloudflare 免费资源（Workers + KV）运行。**

## 🖼️ 预览

> *在此处放入您的后台截图*

## ✨ 核心特性

* **☁️ 无服务器架构**：直接部署在 Cloudflare Workers，依赖 KV 存储。每日 10w 次免费读取，个人使用零成本。
* **🧠 智能清洗与去重**：
    * 自动识别多种格式（`IP:Port`、`IP:Port#备注`、CSV、Telegram 链接）。
    * **智能查询**：对于没有备注的纯 IP，自动调用外部 API 查询国家/地区代码作为备注。
    * **性能优化**：已有备注的节点自动跳过查询，秒级处理上千节点。
    * **自动去重**：基于 `IP:端口` 进行去重，保留最新数据。
* **🤖 Telegram 机器人集成**：
    * 直接向 TG 机器人发送 `.txt` 或 `.csv` 文件，系统自动解析并上传。
    * 支持白名单鉴权，防止未授权访问。
    * 支持文件大小限制（5MB）保护。
* **⚡️ 极速 UI 体验**：
    * 采用 **乐观 UI 更新 (Optimistic UI)** 策略，添加、删除、生成文件无需刷新页面，界面即时响应。
    * 支持自定义数据源名称，列表展示清晰明了。
* **📝 灵活的数据源管理**：
    * **订阅源/API**：支持添加外部链接，支持自定义命名备注。
    * **文件上传**：支持 GBK/UTF-8 编码，完美解决 Excel 导出的 CSV 中文乱码问题。
    * **自定义 IP 池**：手动粘贴 IP 列表。
* **📂 聚合订阅生成**：
    * 可自由组合不同的数据源（配方），生成独立的订阅链接。
    * 支持自动定时更新（需配置 Cron Triggers）。

---

## 🛠️ 部署教程

无需懂代码，只需简单三步即可部署。

### 第一步：准备 Cloudflare 环境

1.  登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)。
2.  进入左侧菜单 **Workers & Pages** -> **KV**。
3.  点击 **Create a Namespace**。
4.  命名为 **`IP_NODES`** (⚠️注意：名称必须完全一致，全大写)。
5.  点击 **Add**。

### 第二步：创建 Worker 并部署代码

1.  进入 **Workers & Pages** -> **Overview** -> **Create Worker**。
2.  给 Worker 起个名字（例如 `node-manager`），点击 **Deploy**。
3.  点击 **Edit code** 进入代码编辑器。
4.  **清空** 编辑器中现有的所有代码。
5.  将本项目中的 `worker.js` (即 v9.9 完整代码) 复制粘贴进去。
6.  点击右上角的 **Deploy**。

### 第三步：配置环境变量与绑定 KV

1.  回到 Worker 的设置页面：**Settings** -> **Variables**。
2.  **绑定 KV Namespace**：
    * 向下滚动到 **KV Namespace Bindings**。
    * 点击 **Add Binding**。
    * **Variable name**: 填写 `IP_NODES` (必须大写)。
    * **KV Namespace**: 选择第一步创建的 `IP_NODES`。
3.  **添加环境变量 (Environment Variables)**：
    * 点击 **Add Variable**。
    * 添加以下变量：

| 变量名 (Variable name) | 说明 | 是否必填 |
| :--- | :--- | :--- |
| `ADMIN_PASSWORD` | 后台管理密码 | **必填** |
| `TG_BOT_TOKEN` | Telegram 机器人 Token (找 @BotFather 获取) | 选填 |
| `TG_WHITELIST_ID` | 你的 Telegram User ID (防止他人上传，找 @userinfobot 获取) | 选填 |

4.  点击 **Save and Deploy**。

---

## 🤖 配置 Telegram 机器人 (可选)

如果你配置了 `TG_BOT_TOKEN`，需要绑定 Webhook 才能接收文件。

1.  构建 Webhook URL：
    ```text
    [https://api.telegram.org/bot](https://api.telegram.org/bot)<你的Token>/setWebhook?url=https://<你的Worker域名>/api/tg_hook
    ```
    * 将 `<你的Token>` 替换为机器人的 Token。
    * 将 `<你的Worker域名>` 替换为你 Worker 的访问域名 (例如 `node-manager.xxx.workers.dev`)。

2.  在浏览器中访问上述 URL。
3.  如果页面返回 `{"ok":true, ... "description":"Webhook was set"}` 即表示成功。
4.  现在，你可以直接在 Telegram 把 `.csv` 或 `.txt` 文件转发给机器人了！

---

## ⏰ 配置自动更新 (可选)

如果你希望生成的订阅文件能自动定时抓取最新数据：

1.  进入 Worker -> **Settings** -> **Triggers**。
2.  点击 **Add Cron Trigger**。
3.  设置执行频率，例如每天凌晨 4 点：`0 4 * * *`。
4.  在后台“生成订阅文件”时，勾选 **“自动更新”** 选项即可。

---

## 📖 使用指南

1.  **登录后台**：访问 `https://你的Worker域名/admin`，输入密码。
2.  **添加数据源**：
    * **上传管理**：上传本地整理好的 IP 文件。
    * **订阅源/API**：添加外部链接，建议填写入名称方便区分。
    * **找资源**：收藏常用的发布 IP 的网站。
3.  **生成订阅**：
    * 进入“文件生成”标签。
    * 输入文件名（例如 `my_subs`）。
    * 勾选你需要组合的数据源（支持多选）。
    * 点击“生成文件”。
4.  **使用**：
    * 复制生成的链接（`https://.../ip/my_subs`）到你的代理软件中使用。

---
<img width="847" height="605" alt="image" src="https://github.com/user-attachments/assets/6e6b0bbe-9f01-4a6f-a3ca-d77184883183" />
<img width="767" height="483" alt="image" src="https://github.com/user-attachments/assets/b995dbce-1f4d-4c7e-83d3-2ae571b24201" />
<img width="766" height="458" alt="image" src="https://github.com/user-attachments/assets/24fc30a9-39e1-47b1-8d8c-2c60cebde11f" />
<img width="770" height="463" alt="image" src="https://github.com/user-attachments/assets/34f2813b-9f20-4b55-9262-68dc3e99c7a4" />





## ⚠️ 免责声明

* 本项目仅供学习 Serverless 架构与 JavaScript 编程之用。
* 请勿将本项目用于任何非法用途。
* 使用本程序产生的一切后果由使用者自行承担。

---

**如果觉得好用，请给个 Star ⭐️！**
