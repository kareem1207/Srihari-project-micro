"""Environment-based configuration. No secrets are hardcoded."""
import os


def database_url() -> str:
    url = os.getenv("SECUREWORK_DATABASE_URL")
    if url:
        return url
    if os.getenv("POSTGRES_HOST"):
        return ("postgresql+psycopg2://{u}:{p}@{h}:{port}/{d}".format(
            u=os.environ["POSTGRES_USER"], p=os.environ["POSTGRES_PASSWORD"],
            h=os.environ["POSTGRES_HOST"], port=os.getenv("POSTGRES_PORT", "5432"),
            d=os.getenv("POSTGRES_DB", "securework")))
    return "sqlite:///data/securework_dev.db"  # lightweight dev fallback only


def jwt_secret() -> str:
    s = os.getenv("SECUREWORK_JWT_SECRET")
    if not s or len(s) < 32:
        raise RuntimeError("Set SECUREWORK_JWT_SECRET (>=32 chars) in the environment")
    return s


JWT_MINUTES = int(os.getenv("SECUREWORK_JWT_MINUTES", "60"))
ES_URL = os.getenv("SECUREWORK_ES_URL", "")           # e.g. http://localhost:9200
ES_INDEX = os.getenv("SECUREWORK_ES_INDEX", "securework-events")
LOG_FILE = os.getenv("SECUREWORK_LOG_FILE", "logs/securework_events.jsonl")
MODEL_PATH = os.getenv("SECUREWORK_MODEL_PATH", "models/nslkdd_ids.joblib")
DEDUP_WINDOW_SECONDS = int(os.getenv("SECUREWORK_DEDUP_SECONDS", "300"))
