"""Configuration du collecteur réseau."""
from pathlib import Path
import os

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

# Racine du projet qui contient le dossier collector/.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

def env_path(name: str, default: Path) -> Path:
    value = os.getenv(name)
    path = Path(value).expanduser() if value else default
    if not path.is_absolute():
        path = (PROJECT_ROOT / path).resolve()
    return path

# Dossier du projet CICFlowMeter contenant gradlew.bat et build.gradle.
CICFLOWMETER_DIR = env_path("CICFLOWMETER_DIR", PROJECT_ROOT)

# Fichier CSV produit par LiveCaptureCli.
CSV_PATH = env_path("CSV_PATH", PROJECT_ROOT / "data" / "live_flows.csv")

# API FastAPI : contrat défini dans l'architecture du projet.
API_URL = os.getenv("API_URL", "http://127.0.0.1:8000/api/v1/flows")
API_TIMEOUT_SECONDS = float(os.getenv("API_TIMEOUT_SECONDS", "15"))
POLL_INTERVAL_SECONDS = float(os.getenv("POLL_INTERVAL_SECONDS", "0.5"))
HTTP_RETRY_SECONDS = float(os.getenv("HTTP_RETRY_SECONDS", "3"))

# Interface par défaut utilisée dans la commande Gradle.
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "7")
APPEND_CSV = os.getenv("APPEND_CSV", "false").lower() in {"1", "true", "yes"}

# False : ignorer les anciennes lignes déjà présentes au démarrage du watcher.
# True : envoyer aussi les lignes déjà présentes dans le CSV.
START_FROM_BEGINNING = os.getenv("START_FROM_BEGINNING", "false").lower() in {"1", "true", "yes"}
