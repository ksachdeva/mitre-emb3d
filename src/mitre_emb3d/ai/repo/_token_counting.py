from pathlib import Path

from litellm.litellm_core_utils.token_counter import token_counter

from ._repo import FsEntry, RepoUnderReview

_MODEL_NAME = "gpt-3.5-turbo"


def _count_tokens_in_file(entry: FsEntry) -> int:
    try:
        content = entry.path.read_text()
        messages = [{"user": "role", "content": content}]
        return token_counter(model=_MODEL_NAME, messages=messages)
    except Exception:
        return 0


def count_tokens(repo: RepoUnderReview) -> dict[Path, int]:
    file_counts: dict[Path, int] = {e.path: _count_tokens_in_file(e) for e in repo.files()}

    dir_counts: dict[Path, int] = {e.path: 0 for e in repo.dirs()}
    for file_path, count in file_counts.items():
        for ancestor in file_path.parents:
            if ancestor == repo.root:
                break
            if ancestor in dir_counts:
                dir_counts[ancestor] += count

    return {**file_counts, **dir_counts}
