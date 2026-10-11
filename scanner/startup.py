"""App Service startup with explicit executable permissions for the private JRE."""
import os
import sys
from pathlib import Path


def main():
    java = os.getenv("JAVA_BIN")
    if java and not Path(java).is_absolute():
        java = str(Path(__file__).resolve().parent.parent / java)
    if java and os.name != "nt" and Path(java).is_file():
        os.chmod(java, 0o755)
    os.execv(sys.executable, [sys.executable, "-m", "uvicorn", "scanner.api:app", "--host", "0.0.0.0", "--port", os.getenv("PORT", "8000"), "--no-access-log", "--limit-concurrency", "16"])


if __name__ == "__main__":
    main()
