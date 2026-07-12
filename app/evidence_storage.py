import os
from pathlib import Path


class LocalEvidenceStorage:
    """Local filesystem storage backend for investigation evidence artifacts."""

    def __init__(self, base_directory: str | Path):
        self.base_directory = Path(base_directory)
        self.base_directory.mkdir(parents=True, exist_ok=True)

    def _case_directory(self, case_id: str) -> Path:
        directory = self.base_directory / case_id
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def save_bytes(self, *, case_id: str, filename: str, data: bytes) -> Path:
        destination = self._case_directory(case_id) / filename
        destination.write_bytes(data)
        return destination

    def get_path(self, *, case_id: str, filename: str) -> Path:
        return self.base_directory / case_id / filename

    def exists(self, *, case_id: str, filename: str) -> bool:
        return self.get_path(case_id=case_id, filename=filename).exists()

    def delete(self, *, case_id: str, filename: str) -> None:
        path = self.get_path(case_id=case_id, filename=filename)
        if path.exists():
            path.unlink()


DEFAULT_EVIDENCE_STORAGE_PATH = os.getenv(
    "EVIDENCE_STORAGE_PATH",
    str(Path(__file__).resolve().parent.parent / "evidence_repository"),
)

storage_backend = LocalEvidenceStorage(DEFAULT_EVIDENCE_STORAGE_PATH)
