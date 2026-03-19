from pathlib import Path

from mitre_emb3d.ai.repo import FsEntry, RepoUnderReview, count_tokens


class NaiveContextProvider:
    def __init__(self, repo: RepoUnderReview) -> None:
        self._repo = repo
        self._tokens: dict[Path, int] = count_tokens(repo)

    def get_context(
        self,
        max_tokens: int,
        file_set: list[Path] | None = None,
    ) -> list[list[FsEntry]]:
        batches: list[list[FsEntry]] = []
        current_batch: list[FsEntry] = []
        current_tokens = 0

        files_to_process: list[FsEntry] = []

        if file_set is not None:
            # we need to append the root path to the file_set entries since the repo entries are absolute paths
            file_set = [f if f.is_absolute() else self._repo.root / f for f in file_set]

            for entry in self._repo.files():
                if entry.path not in file_set:
                    continue
                files_to_process.append(entry)
        else:
            files_to_process = list(self._repo.files())

        for entry in files_to_process:
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
