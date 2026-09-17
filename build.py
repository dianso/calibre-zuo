# -*- coding: utf-8 -*-
"""
Calibre-ZUO 插件打包脚本。
把 src/ 目录压缩为 Calibre 可直接「从文件加载插件」的 zip 包。
产出路径：out/Calibre-ZUO.zip
"""
import os
import shutil
import zipfile

OUT_DIR = "out"
OUT_ZIP = os.path.join(OUT_DIR, "Calibre-ZUO.zip")
SRC_DIR = "src"


def zip_src(src_dir: str, zip_path: str) -> None:
    """递归压缩源码目录为 zip，跳过 __pycache__ 与 .pyc 产物。"""
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as bundle:
        for root, dirs, files in os.walk(src_dir):
            # 排除字节码缓存目录
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            rel_root = os.path.relpath(root, src_dir)
            for name in files:
                if name.endswith(".pyc"):
                    continue
                rel_path = os.path.join(rel_root, name)
                # zip 内统一以文件名/相对路径归档，__init__.py 位于包根即可被 Calibre 识别
                arcname = name if rel_root == "." else rel_path
                print(f"打包文件: {os.path.join(root, name)} -> {arcname}")
                bundle.write(os.path.join(root, name), arcname)


def main() -> None:
    if os.path.exists(OUT_DIR):
        shutil.rmtree(OUT_DIR)
    os.makedirs(OUT_DIR, exist_ok=True)
    zip_src(SRC_DIR, OUT_ZIP)
    print(f"插件已输出到: {os.path.abspath(OUT_ZIP)}")


if __name__ == "__main__":
    main()