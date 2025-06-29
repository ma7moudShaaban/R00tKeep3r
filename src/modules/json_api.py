import json
import os

class JSONHandler:
    def __init__(self):
        self.json_path = "/tmp/keep3rs.json"
        
    def read_json(self):
        """Read JSON data."""
        if not os.path.exists(self.json_path):
            return {}
        with open(self.json_path, "r") as f:
            return json.load(f)
    
    def write_json(self, data):
        """Write data to JSON, preserving existing keys."""
        existing_data = self.read_json()
        merged_data = {**existing_data, **data}
        with open(self.json_path, "w") as f:
            json.dump(merged_data, f, indent=2)
    
    def get_priority(self):
        """Fetch escalation priority from JSON."""
        data = self.read_json()
        return data.get("priority", [])