from dataclasses import dataclass, asdict
from datetime import datetime

@dataclass
class TestCase:
    name: str
    description: str
    token: str
    result: dict
    created_at: str = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self):
        return asdict(self)
