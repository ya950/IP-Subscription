# ⚡️ Cloudflare Workers 优选IP管理系统 (v10.7)

![Version](https://img.shields.io/badge/Version-v10.7-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Cloudflare%20Workers-orange?style=flat-square)
![Storage](https://img.shields.io/badge/Storage-R2%20%2B%20KV-green?style=flat-square)

这是一个基于 Cloudflare Workers + KV + R2 构建的无服务器（Serverless）代理优选IP管理系统。它提供了一个功能强大的 Web 界面，用于聚合、提取、去重、测试和管理您的优选IP。

**v10.7 版本重点修复了浏览器缓存导致的文件回滚问题，并增强了对 URL-Safe Base64 的解码支持。**

## 在线演示:https://ip.xill.de5.net/   密码123

## 📸 界面预览


| 主控制台 / 数据源管理 | 提取与测试 |
| :---: | :---: |
| ![Extract](https://imgbed.1990909.xyz/file/blog/1765508174044_image.png) | 
| ![Extract](https://imgbed.1990909.xyz/file/blog/1765479271932_image.png) |

## ✨ 核心功能

* **多源聚合**: 支持订阅链接（提取订阅链接IP和端口以及备注）、API 接口、自定义文本、本地文件/TG上传（支持 CSV/TXT）等多种数据源。
    * 支持订阅链接:可以从别人订阅链接提取IP,端口和备注
    * API 接口：公开的txt文本url
    * 自定义文本：可以自由组合ip
    * 本地文件上传：支持本地和TG上传CSV/TXT
    * 文件生成：可以从IP源获取的IP自由组合生成你想要的IP做为API使用
    * 在线编辑：更加强大的自定义，无限生成多个API文件（如生成日本的优选API，美国优选API等等）
    * 更多功能自寻探索......
* **智能提取**:
    * 支持解析 Vmess, Vless, Trojan, SS, SSR 等多种协议。
    * **v10.7 增强**: 深度优化 Base64 解码，支持 URL-Safe 字符 (`-`, `_`)，解决部分机场订阅无法识别的问题。
* **文件管理 (R2)**:
    * 利用 Cloudflare R2 存储生成的订阅文件，支持大文件和高并发访问。
    * 提供 **可编辑文件** 功能，可在网页端直接编辑 IP 列表，实时保存（**v10.7 修复了缓存回滚 Bug**）。
* **自动更新**: 集成 Cron Triggers，支持定时自动拉取订阅源并更新目标文件。
* **查询工具**: 内置 IP 归属地查询工具，支持批量去重和国家代码检测。
* **Telegram 机器人**:
    * 支持直接向机器人发送 `.txt` 或 `.csv` 文件进行自动上传。
    * 简单的权限验证机制。

## 📝 v10.7 更新日志

1.  **[修复] 缓存问题**: 彻底解决了可编辑文件保存后，因浏览器强缓存导致刷新页面时列表回退、文件“消失”的严重 Bug。
2.  **[修复] Base64 增强**: 重写了解析逻辑，完美支持 URL-Safe Base64 编码，修复了部分加密订阅源无法提取 IP 的问题。
3.  **[优化] 元数据同步**: 优化了 R2 存储与 KV 索引之间的同步逻辑，防止数据不一致。

## 🛠 部署教程

### 1. 准备工作
* 一个 Cloudflare 账号。
* 开通 Workers、KV 和 R2 服务（免费额度足够个人使用）。

### 2. 创建资源
1.  **KV Namespace**:
    * 创建一个名为 `IP_NODES` 的 KV 命名空间。
2.  **R2 Bucket**:
    * 创建一个名为 `node-files` 的存储桶。

### 3. 部署 Worker
1.  在 Cloudflare Dashboard 创建一个新的 Worker。
2.  将本项目 `worker.js` 的所有代码复制并覆盖到编辑器中。
3.  **绑定变量** (Settings -> Variables):

    | 变量类型 | 变量名称 (Variable Name) | 对应值/资源 | 说明 |
    | :--- | :--- | :--- | :--- |
    | **KV Namespace** | `IP_NODES` | 选择你创建的 `IP_NODES` | **必须一致** |
    | **R2 Bucket** | `NODE_FILES` | 选择你创建的 `node-files` | **必须一致** |
    | **Environment Variable** | `ADMIN_PASSWORD` | `设置你的登录密码` | **必填** |
    | **Environment Variable** | `TG_BOT_TOKEN` | `123456:ABC-Def...` | (选填) TG Bot Token |
    | **Environment Variable** | `TG_WHITELIST_ID` | `123456789` | (选填) 你的 TG Chat ID |

4.  点击 **Deploy** 部署。

### 4. 配置定时任务 (可选)
如果需要订阅自动更新功能，请在 Worker 的 **Triggers** -> **Cron Triggers** 中添加触发器：
* 建议频率: `0 */2 * * *` (每2小时执行一次)

### 5. 配置 Telegram Webhook (可选)
如果你配置了 `TG_BOT_TOKEN`，请在浏览器访问以下 URL 以激活机器人文件接收功能：

https://api.telegram.org/bot<你的Token>/setWebhook?url=https://<你的Worker域名>/api/tg_hook

## 🖥 使用说明

1.  访问你的 Worker 域名 (e.g., `https://xxx.workers.dev/admin`)。
2.  输入环境变量中设置的 `ADMIN_PASSWORD` 进行登录。
3.  **添加订阅**: 在“IP来源”页签添加你的机场订阅链接。
4.  **生成文件**: 在“文件生成”页签，勾选需要的订阅源，设置文件名（如 `my_subs`），点击生成。
5.  **获取链接**: 生成成功后，你将获得一个 **Workers 链接** (动态) 和一个 **R2 直链** (静态)，均可导入 Clash 或 V2Ray 使用。

## ⚠️ 免责声明

* 本项目仅供技术研究和学习使用。
* 请勿用于任何违反当地法律法规的用途。
* 开发者不对使用本项目产生的任何后果负责。

---
**如果觉得这个项目对你有帮助，欢迎点个 Star ⭐️！**
