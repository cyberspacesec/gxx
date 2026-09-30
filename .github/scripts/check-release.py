#!/usr/bin/env python3
"""核对完整的发布平台、ZIP 内容和 SHA-256 校验和。"""

import hashlib
from pathlib import Path, PurePosixPath
import sys
import zipfile


def main():
    directory = Path(sys.argv[1])
    version = sys.argv[2]
    platforms = {
        "gxx": ("mac_x64", "mac_arm64", "linux_x64", "linux_arm64", "win_x64", "win_arm64"),
        "gxx-ide": ("mac_x64", "mac_arm64", "win_x64"),
    }
    expected = {f"{product}_{platform}_{version}.zip" for product, items in platforms.items() for platform in items}
    actual = {path.name for path in directory.glob("*.zip")}
    if actual != expected:
        raise ValueError(f"发布包不完整：缺少 {sorted(expected - actual)}；多余 {sorted(actual - expected)}")

    checksums = []
    for name in sorted(expected):
        path = directory / name
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if not entries or archive.testzip() is not None:
                raise ValueError(f"无效的发布包：{name}")
            for entry in entries:
                member = PurePosixPath(entry.filename.replace("\\", "/"))
                if member.is_absolute() or ".." in member.parts:
                    raise ValueError(f"发布包包含不安全的路径：{name}: {entry.filename}")
                if any(part in {".git", ".gitlab"} or (part.startswith(".gitlab-ci") and part.endswith((".yml", ".yaml"))) for part in member.parts):
                    raise ValueError(f"发布包包含 Git 元数据或 GitLab 配置：{name}: {entry.filename}")
            if name.startswith("gxx_"):
                executable = "gxx.exe" if "_win_" in name else "gxx"
                if executable not in archive.namelist():
                    raise ValueError(f"CLI 发布包缺少可执行文件：{name}")
            elif "_win_" in name:
                if "gxx-ide.exe" not in archive.namelist():
                    raise ValueError(f"IDE 发布包缺少可执行文件：{name}")
            elif not any(part.endswith(".app") for entry in entries for part in PurePosixPath(entry.filename).parts):
                raise ValueError(f"macOS IDE 发布包缺少应用：{name}")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        checksums.append(f"{digest}  {name}\n")
    (directory / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")
    print(f"核对通过：{len(expected)} 个发布包，已生成 SHA256SUMS")


if __name__ == "__main__":
    main()
