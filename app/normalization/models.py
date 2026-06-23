from datetime import datetime

from pydantic import BaseModel, ConfigDict


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    host: str
    user: str | None = None
    process_name: str
    parent_process: str | None = None
    command_line: str | None = None
    hash_sha256: str | None = None
    event_type: str
    source: str
