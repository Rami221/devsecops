import json
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo  # Disponible en Python 3.9+

class JSONLogger:
    @staticmethod
    def log(service: str, event: str, data: dict):
        log_entry = {
            "timestamp": datetime.now(ZoneInfo("Africa/Tunis")).isoformat(),
            "service": service,
            "event": event,
            "data": data,
            "log_id": str(uuid.uuid4())
        }
        print(json.dumps(log_entry))
