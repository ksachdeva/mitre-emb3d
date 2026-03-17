from __future__ import annotations

from collections import Counter
from enum import Enum
from pathlib import Path, PurePath
from typing import Any

import pathspec
from git import Repo
from pathspec.patterns.gitignore.spec import GitIgnoreSpecPattern
from pydantic import BaseModel

_PRE_BAKED_IGNORE_PATTERNS = [
    "**/node_modules/**",
    "**/.git/**",
    "**/bower_components/**",
    "**/.svn/**",
    "**/.hg/**",
    "**/*.gitkeep",
    "**/*.gitignore",
    "**/*.bin",
    "**/*.exe",
    "**/*.dll",
    "**/*.so",
    "**/*.dylib",
    "**/*.class",
    "**/*.jar",
    "**/*.war",
    "**/*.zip",
    "**/*.tar",
    "**/*.gz",
    "**/*.bz2",
    "**/*.rar",
    "**/*.7z",
    "**/*.doc",
    "**/*.docx",
    "**/*.xls",
    "**/*.xlsx",
    "**/*.ppt",
    "**/*.pptx",
    "**/*.odt",
    "**/*.ods",
    "**/*.odp",
    "**/*.cmake",
    "**/*.ps1",
    "**/*.psm1",
    "**/.env",
    "**/.env.example",
    "**/*.pdf",
    "**/*.png",
    "**/*.jpg",
    "**/*.jpeg",
    "**/*.gif",
    "**/*.webp",
    "**/*.bmp",
    "**/*.svg",
    "**/CMakeLists.txt",
    "**/.vscode/**",
    "**/.idea/**",
    "**/coverage/**",
    "**/__pycache__/**",
    "**/.devcontainer/**",
    "**/.clang-format",
    "**/Jenkinsfile",
    "**/uv.lock",
    "**/pyproject.toml",
    "**/*.pyc",
    "**/*.pyo",
    "**/.DS_Store",
    "**/.gitattributes",
    "**/.editorconfig",
    "**/.pre-commit-config.yaml",
    "**/.python-version",
    "**/LICENSE",
    "**/*.code-workspace",
    "**/poe.toml",
]


class FsEntryKind(str, Enum):
    FILE = "file"
    DIR = "dir"


class StatInfo(BaseModel):
    size: int
    mtime: float
    mode: int

    @classmethod
    def from_path(cls, path: Path) -> StatInfo:
        s = path.stat()
        return cls(size=s.st_size, mtime=s.st_mtime, mode=s.st_mode)


class FsEntry(BaseModel):
    path: Path
    kind: FsEntryKind
    stat: StatInfo

    @classmethod
    def from_path(cls, path: Path, kind: FsEntryKind) -> FsEntry:
        return cls(path=path, kind=kind, stat=StatInfo.from_path(path))


class RepoUnderReview(BaseModel):
    root: Path
    entries: list[FsEntry]

    @classmethod
    def from_repo(
        cls,
        repo_path: Path,
        ignore_patterns: list[str] | None = None,
    ) -> RepoUnderReview:
        root = repo_path.resolve()
        repo = Repo(root)

        # git ls-files — respects .gitignore automatically
        tracked = repo.git.ls_files().splitlines()

        total_ignore_patterns = _PRE_BAKED_IGNORE_PATTERNS + (ignore_patterns or [])

        spec = pathspec.PathSpec.from_lines(GitIgnoreSpecPattern, total_ignore_patterns)
        tracked = [f for f in tracked if not spec.match_file(f)]

        # derive unique directory paths from all tracked file paths
        dir_paths: set[Path] = set()
        for rel in tracked:
            for ancestor in (root / rel).parents:
                if ancestor == root:
                    break
                dir_paths.add(ancestor)

        entries: list[FsEntry] = [FsEntry.from_path(root / rel, FsEntryKind.FILE) for rel in tracked] + [
            FsEntry.from_path(d, FsEntryKind.DIR) for d in sorted(dir_paths)
        ]

        return cls(root=root, entries=entries)

    def files(self) -> list[FsEntry]:
        return [e for e in self.entries if e.kind == FsEntryKind.FILE]

    def dirs(self) -> list[FsEntry]:
        return [e for e in self.entries if e.kind == FsEntryKind.DIR]

    def files_under(self, directory: Path) -> list[FsEntry]:
        resolved = directory if directory.is_absolute() else self.root / directory
        return [e for e in self.files() if e.path.is_relative_to(resolved)]

    def dirs_under(self, directory: Path) -> list[FsEntry]:
        resolved = directory if directory.is_absolute() else self.root / directory
        return [e for e in self.dirs() if e.path.is_relative_to(resolved)]

    def files_by_extension(self, ext: str) -> list[FsEntry]:
        normalized = ext if ext.startswith(".") else f".{ext}"
        return [e for e in self.files() if e.path.suffix == normalized]

    def find(self, glob: str) -> list[FsEntry]:
        return [e for e in self.entries if PurePath(e.path).match(glob)]

    def relative_paths(self) -> list[Path]:
        return [e.path.relative_to(self.root) for e in self.entries]

    def tree(self) -> dict[str, Any]:
        """Nested dict of path components. File leaves hold the FsEntry; dirs are dicts."""
        result: dict[str, Any] = {}
        for entry in self.files():
            rel = entry.path.relative_to(self.root)
            node = result
            for part in rel.parts[:-1]:
                node = node.setdefault(part, {})
            node[rel.parts[-1]] = entry
        return result

    def extension_counts(self) -> dict[str, int]:
        """Return a mapping of file extension -> file count, sorted by count descending."""
        counter: Counter[str] = Counter()
        for entry in self.files():
            ext = entry.path.suffix or "(no extension)"
            counter[ext] += 1
        return dict(counter.most_common())
