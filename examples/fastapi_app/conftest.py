import os
import tempfile

# main.py reads these at import time
_tmp = tempfile.mkdtemp(prefix="safe-api-keys-fastapi-")
os.environ.setdefault("SAFE_API_KEYS_PEPPER", "test-pepper-32-bytes-xxxxxxxxxxxxx")
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{os.path.join(_tmp, 'example.db')}")
