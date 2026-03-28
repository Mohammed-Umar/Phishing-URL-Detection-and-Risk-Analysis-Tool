import json
import os
from datetime import datetime

class HistoryManager:
    """Manages history of checked URLs."""

    def __init__(self, file_path="history.json"):
        self.file_path = file_path
        if not os.path.exists(self.file_path):
            with open(self.file_path, "w") as f:
                json.dump([], f)

    def add_to_history(self, url, score, level, reasons):
        """Adds a new entry to the history."""
        try:
            with open(self.file_path, "r") as f:
                history = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            history = []

        entry = {
            "timestamp": datetime.now().isoformat(),
            "url": url,
            "score": score,
            "level": level,
            "reasons": reasons
        }
        
        # Avoid duplicate consecutive entries
        if history and history[0]["url"] == url:
            return 
            
        history.insert(0, entry)  # Prepend newest
        history = history[:50]  # Store last 50 only

        with open(self.file_path, "w") as f:
            json.dump(history, f, indent=4)

    def get_history(self):
        """Retrieves history entries."""
        try:
            with open(self.file_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
