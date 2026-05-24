import os
import shutil
import pathlib

def sanitize_project():
    root = pathlib.Path(__file__).parent
    
    # 1. 定义消杀目标
    targets = {
        "dirs": [
            "__pycache__", 
            ".pytest_cache", 
            "release", 
            "build", 
            "dist",
            "SpaceCleaner_Quarantine"  # 开发测试用的隔离箱
        ],
        "files": [
            "state_file.json",         # 重置状态机
            ".first_run",               # 重置欢迎语标志 [cite: 8]
            "spacecleaner.log",        # 清除调试日志 [cite: 8]
            "*.spec"                   # 清除 PyInstaller 配置文件
        ]
    }

    print("🚀 开始发布前强制消杀...")

    # 2. 清理目录
    for d in targets["dirs"]:
        dir_path = root / d
        if dir_path.exists():
            shutil.rmtree(dir_path)
            print(f"[已擦除目录] {d}")

    # 3. 清理文件与匹配符
    for f in targets["files"]:
        if "*" in f:
            for match in root.glob(f):
                match.unlink()
                print(f"[已粉碎文件] {match.name}")
        else:
            file_path = root / f
            if file_path.exists():
                file_path.unlink()
                print(f"[已重置文件] {f}")

    print("✨ 项目已恢复『处子状态』，可以开始 Nuitka 编译。")

if __name__ == "__main__":
    sanitize_project()
3. 费曼类比 (Feynman Analogy)