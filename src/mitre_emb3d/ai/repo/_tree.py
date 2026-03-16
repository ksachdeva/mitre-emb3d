from __future__ import annotations

from pathlib import Path
from typing import List

from mitre_emb3d.ai.repo._repo import RepoUnderReview

from ._token_counting import count_tokens


def _format_tokens(count: int) -> str:
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    if count >= 1_000:
        return f"{count / 1_000:.1f}k"
    return f"{count}"


class RepoTreeGenerator:
    def __init__(
        self,
        repo: RepoUnderReview,
        max_level: int | None = None,
        sort_order: str = "standard",
        dirs_only: bool = False,
        token_counts: dict[Path, int] | None = None,
    ) -> None:
        self._max_level = max_level
        self._sort_order = sort_order
        self._dirs_only = dirs_only
        self._repo = repo
        self._token_counts = token_counts
        self._tree_str: List[str] = []

    @classmethod
    def from_repo(
        cls,
        repo: RepoUnderReview,
        max_level: int | None = None,
        sort_order: str = "standard",
        dirs_only: bool = False,
        show_token_counts: bool = False,
    ) -> RepoTreeGenerator:
        token_counts = count_tokens(repo) if show_token_counts else None
        return cls(
            repo=repo,
            max_level=max_level,
            sort_order=sort_order,
            dirs_only=dirs_only,
            token_counts=token_counts,
        )

    def _get_direct_children(self, directory: Path) -> List[Path]:
        """Return direct children of *directory* sourced from the RepoUnderReview."""
        assert self._repo is not None
        return [e.path for e in self._repo.entries if e.path.parent == directory]

    def _filter_items(self, items: List[Path]) -> List[Path]:
        """Filter items based on settings."""
        filtered_items = items

        # Apply all filters
        filtered_items = [item for item in filtered_items if not (self._dirs_only and not item.is_dir())]

        return filtered_items

    def _sort_items(self, items: List[Path]) -> List[Path]:
        """Sort items based on the specified sort order."""
        items = self._filter_items(items)

        if self._sort_order == "standard":
            # Separate directories and files
            dirs = sorted([item for item in items if item.is_dir()])
            files = [] if self._dirs_only else sorted([item for item in items if item.is_file()])
            return dirs + files
        else:
            # Sort all items together
            return sorted(items, reverse=(self._sort_order == "desc"))

    def _generate_tree(
        self,
        directory: Path,
        prefix: str = "",
        level: int = 0,
    ) -> None:
        if self._max_level is not None and level > self._max_level:
            return

        # Add current directory to tree
        if level == 0:
            root_label = directory.name + "/"
            if self._token_counts is not None and directory in self._token_counts:
                root_label += f"  [{_format_tokens(self._token_counts[directory])}]"
            self._tree_str.append(root_label)

        # Get all items in the directory
        try:
            items = self._get_direct_children(directory)
            items = self._sort_items(items)
        except PermissionError:
            self._tree_str.append(f"{prefix}├── [Permission Denied]")
            return
        except OSError as e:
            self._tree_str.append(f"{prefix}├── [Error: {str(e)}]")
            return

        # Process each item
        for i, item in enumerate(items):
            is_last = i == len(items) - 1
            item_prefix = prefix + ("└── " if is_last else "├── ")
            next_prefix = prefix + ("    " if is_last else "│   ")

            if item.is_dir():
                label = f"{item_prefix}{item.name}/"
                if self._token_counts is not None and item in self._token_counts:
                    label += f"  [{_format_tokens(self._token_counts[item])}]"
                self._tree_str.append(label)
                self._generate_tree(item, next_prefix, level + 1)
            elif not self._dirs_only:
                label = f"{item_prefix}{item.name}"
                if self._token_counts is not None and item in self._token_counts:
                    label += f"  [{_format_tokens(self._token_counts[item])}]"
                self._tree_str.append(label)

    def get_tree(self) -> str:
        """Generate and return the tree as a string."""
        self._tree_str = []
        self._generate_tree(self._repo.root)
        return "\n".join(self._tree_str)
