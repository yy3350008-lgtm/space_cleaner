# 释放空间助手

一个面向 Windows 的交互式命令行工具，用于安全扫描、隔离和归档无用安装包及临时文件。

## 快速入口
- 新手先看：`START_HERE.md`
- 详细使用：`docs/USAGE.md`
- 发布交付：`docs/发布使用清单.md`

## 1. 系统要求
- Windows 10+
- Python 3.10+

如果是发给不懂 Python 的小白，建议直接打包成 `exe` 或便携 `zip`。这样用户不需要安装 Python，也不需要打开编辑器，双击启动脚本或直接运行 `SpaceCleaner.exe` 就能用。

## 2. 首次使用流程（扫描 -> 确认 -> 归档）
1. 运行 `python main.py`
2. 选择快速扫描或自定义扫描
3. 查看预览报告并在确认菜单输入“我确认”
4. 程序将文件移动到隔离区，可选 ZIP 归档

### 智能扫描并建议压缩（目录内快捷动作）
在自定义目录浏览中可直接触发“智能扫描并建议压缩”：
1. 仅扫描当前目录并列出推荐候选
2. 一次确认后直接进入隔离与归档
3. 不会自动删除，删除仍需手动进入清理菜单

### 极限释放（高级）
当你需要最大化释放空间时，可使用“极限释放”入口：
1. 先完成隔离与归档
2. 系统执行十项安全检查
3. 仅在三重人工确认后，才清理隔离副本

## 3. 如何恢复文件（长期恢复）
1. 打开程序，选择“查看并恢复历史归档”
2. 根据 manifest CSV 找到 `original_path` 与 `quarantine_path`
3. 调用 `recovery.restore_file()` 或从 ZIP 使用 `restore_from_zip()`
4. 恢复后状态会更新为 `restored`

## 4. 如何添加自定义扫描目录
- 主菜单选择“添加自定义扫描目标”
- 输入目录路径后，本次运行会临时追加到 `scan_targets`

## 5. config.json 字段说明
- `scan_targets`: 默认扫描路径
- `quarantine_dir`: 隔离区目录
- `report_dir`: 报告目录；空字符串表示程序目录
- `exclude_dirs`: 排除目录
- `exclude_extensions`: 排除扩展名
- `max_file_age_days`: 文件最小年龄（天）；0 表示不限制
- `min_file_size_kb`: 最小文件大小
- `dry_run_by_default`: 默认 Dry-run
- `quarantine_ttl_days`: 隔离文件过期天数
- `rule_source`: 规则来源（builtin/online 预留）

## 6. 如何更新规则
编辑 `rules/builtin_rules.json`：
- `name_patterns` 文件名关键词
- `suffix_patterns` 后缀关键词
- `target_extensions` 重点扩展名
- `companion_extensions` 关联依赖扩展名

## 7. 隔离区位置与清理
- 默认隔离区：`%USERPROFILE%\\SpaceCleaner_Quarantine`
- 主菜单可查看隔离区文件数量和大小
- 过期文件由 TTL 提醒后手动清理

## 8. 杀毒误报处理
本程序会批量移动文件，可能触发 Windows Defender 的启发式扫描。
若被误报，请在 Windows 安全中心 > 病毒和威胁防护 > 排除项 中添加本程序路径。
本程序所有源码公开，欢迎审计。

## 打包建议
### Nuitka（优先）
```bash
python -m nuitka \
  --onefile \
  --windows-console-mode=attach \
  --include-data-files=config.json=config.json \
  --include-data-dir=rules=rules \
  --windows-product-name="释放空间助手" \
  --windows-file-version=1.0.0.0 \
  --output-filename=SpaceCleaner.exe \
  main.py
```

### PyInstaller（备选）
```bash
pyinstaller --onefile --console \
  --add-data "config.json;." \
  --add-data "rules;rules" \
  --name SpaceCleaner \
  main.py
```
