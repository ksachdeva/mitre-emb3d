from pathlib import Path

from mitre_emb3d.ai.repo import FsEntry, RepoUnderReview, count_tokens


class NaiveContextProvider:
    def __init__(self, repo: RepoUnderReview) -> None:
        self._repo = repo
        self._tokens: dict[Path, int] = count_tokens(repo)

    def get_context(self, max_tokens: int) -> list[list[FsEntry]]:
        batches: list[list[FsEntry]] = []
        current_batch: list[FsEntry] = []
        current_tokens = 0

        for entry in self._repo.files():
            token_count = self._tokens.get(entry.path, 0)
            if current_batch and current_tokens + token_count > max_tokens:
                batches.append(current_batch)
                current_batch = []
                current_tokens = 0
            current_batch.append(entry)
            current_tokens += token_count

        if current_batch:
            batches.append(current_batch)

        return batches
