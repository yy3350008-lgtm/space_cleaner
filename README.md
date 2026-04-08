# 🚀 释放空间助手 (Space Cleaner Assistant)

[![OS](https://img.shields.io/badge/OS-Windows%2010%2B-blue?logo=windows)](https://www.microsoft.com/windows)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green?logo=python)](https://www.python.org/)
[![Safety](https://img.shields.io/badge/Safety-Atomic%20State%20Machine-red)](safety.py)

> **磁盘没地了？不敢乱删？**
> 这是一个专为 Windows 用户设计的安全清理工具。我们不搞暴力粉碎，只做透明、可回溯的“搬运工”----压缩为目的，清除您做主。

---

## ✨ 核心亮点

* **零输入交互**：自动通过注册表嗅探微信、QQ 等重灾区路径，小白无需手敲路径。
* **物理层透明**：主菜单一键弹出“隔离箱”文件夹，让你亲眼看到文件被安全“关禁闭”。
* **后悔药机制**：默认仅隔离与归档。只有当你确认系统稳定，并完成三重手动确认后，才会彻底释放空间。
* **原子状态机**：支持断电恢复，绝不产生“既不在原位也不在隔离箱”的幽灵文件。

---

## 🛠️ 快速开始

### 方式 A：普通用户 (推荐)
1.  前往 [Releases](../../releases) 下载最新的 `SpaceCleaner.exe`。
2.  **双击运行**，跟随终端里的黄色小手 👉 指引操作即可。

### 方式 B：开发者
```bash
# 克隆仓库
git init
git clone [https://github.com/你的用户名/space_cleaner.git](https://github.com/你的用户名/space_cleaner.git)

# 安装依赖
pip install -r requirements.txt

# 运行
python main.py

🛡️ 杀毒误报说明
由于程序涉及批量跨盘移动文件，且没有昂贵的商业数字签名，Windows Defender 可能会报警。

这是正常现象：程序源码完全公开，欢迎审计。

建议：在 Windows 安全中心将程序所在目录添加为“排除项”。