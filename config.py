from pathlib import Path
import yaml

CONFIG_PATH = Path(__file__).parent / "config.yaml"

try:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        _cfg = yaml.safe_load(f) or {}
except FileNotFoundError:
    _cfg = {}

# Backwards compatible top-level constants
KC_BASE = _cfg.get("keycloak", {}).get("base_url", "http://localhost:8080/")
REALM = _cfg.get("keycloak", {}).get("realm", "fastapi_realm")
CLIENT_ID = _cfg.get("keycloak", {}).get("client_id", "fast_api_client")
CLIENT_SECRET = _cfg.get("keycloak", {}).get("client_secret", "")

class Config:
    KC_BASE = KC_BASE
    REALM = REALM
    CLIENT_ID = CLIENT_ID
    CLIENT_SECRET = CLIENT_SECRET
