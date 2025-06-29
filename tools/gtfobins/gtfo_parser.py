import os
import json

class GTFOParser:
    def __init__(self, json_path=None):
        """
        Initialize the GTFOBins parser by loading the JSON file.
        If no path is provided, it loads 'GTFOBins.json' relative to this file.
        """
        if json_path is None:
            json_path = os.path.join(os.path.dirname(__file__), "GTFOBins.json")
        try:
            with open(json_path, "r") as f:
                self.gtfobins = json.load(f)
        except Exception as e:
            print(f"Error loading GTFOBins JSON file '{json_path}': {e}")
            self.gtfobins = {}

    def _match_key(self, base_binary):
        """
        Iterate through the GTFOBins JSON keys to find a match for base_binary.
        Returns the entry if the key exactly matches or if the key starts with base_binary 
        followed by a dot.
        """
        base_binary = base_binary.lower()
        for key, entry in self.gtfobins.items():
            key_lower = key.lower()
            if key_lower == base_binary or key_lower.startswith(base_binary + "."):
                return entry
        return None

    def get_suid_command(self, binary):
        """
        Get the SUID exploit command for a given binary.
        Extract the basename from the path and perform a case-insensitive lookup.
        Allows for matches where the JSON key is the base name or the base name with an extension.
        """
        base_binary = os.path.basename(binary)
        entry = self._match_key(base_binary)
        if entry is not None:
            return entry.get("functions", {}).get("suid", [{}])[0].get("code")
        return None

    def get_sudo_command(self, binary):
        """
        Get the sudo exploit command for a given binary.
        Extract the basename from the path and perform a case-insensitive lookup,
        allowing a match if the key equals the base name or if it starts with it followed by a dot.
        """
        base_binary = os.path.basename(binary)
        entry = self._match_key(base_binary)
        if entry is not None:
            return entry.get("functions", {}).get("sudo", [{}])[0].get("code")
        return None

