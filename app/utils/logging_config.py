"""Application logging setup."""
import logging
from pathlib import Path


def configure_logging() -> None:
    """Write application logs to logs/securework_ai.log and the console."""
    project_root = Path(__file__).resolve().parents[2]
    log_dir = project_root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[
            logging.FileHandler(log_dir / "securework_ai.log", encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )
