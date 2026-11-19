"""Surveille le CSV de CICFlowMeter et transmet chaque flow terminé à FastAPI.

Le lecteur ne traite que les lignes terminées par un saut de ligne. Cela évite
d'envoyer une ligne pendant que Java est encore en train de l'écrire.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import sys
import time
from pathlib import Path
from typing import Any

import requests

from . import config

ROOT = Path(__file__).resolve().parent
MAPPING_PATH = ROOT / "feature_mapping.json"
MODEL_FEATURES = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))["features"]
ALIASES = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))["aliases"]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("csv-watcher")
log.info("FICHIER PYTHON EXECUTE : %s", Path(__file__).resolve())


def to_number(value: Any, feature_name: str) -> int | float:
    """Convertit une valeur CSV en nombre, sans laisser passer NaN/Infinity."""
    if value is None or str(value).strip() == "":
        raise ValueError(f"Valeur vide pour la caractéristique {feature_name!r}")
    number = float(str(value).strip())
    if not math.isfinite(number):
        raise ValueError(f"Valeur non finie pour {feature_name!r}: {value!r}")
    # Évite d'envoyer 42.0 pour les colonnes entières, sans forcer toutes les
    # caractéristiques à être des entiers.
    return int(number) if number.is_integer() else number


def build_payload(row: dict[str, str]) -> dict[str, Any]:
    """Traduit les noms CICFlowMeter vers les 70 noms attendus par le modèle."""
    features: dict[str, int | float] = {}
    missing: list[str] = []

    for model_name in MODEL_FEATURES:
        csv_name = model_name if model_name in row else ALIASES.get(model_name)
        if not csv_name or csv_name not in row:
            missing.append(f"{model_name} (colonne CSV recherchée: {csv_name})")
            continue
        try:
            features[model_name] = to_number(row[csv_name], model_name)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

    if missing:
        raise ValueError("Colonnes absentes du CSV : " + "; ".join(missing))

    flow_id = (row.get("Flow ID") or "").strip()
    if not flow_id:
        # Le Flow ID est fourni par CICFlowMeter ; ce fallback facilite les
        # tests avec des CSV qui n'auraient pas cette colonne.
        flow_id = f"{row.get('Src IP','?')}:{row.get('Src Port','?')}-{row.get('Dst IP','?')}:{row.get('Dst Port','?')}-{row.get('Timestamp','?')}"

    # Le contrat de l'API documenté dans le projet est :
    # { "flow_id": "...", "features": { "<nom exact modèle>": valeur, ... } }
    x = {
        "flow_id":flow_id,
        "src_ip": row.get('Src IP','?'),
        "dst_ip": row.get('Dst IP','?'),
        "src_port": row.get('Src Port','?'),
        "dst_port": row.get('Dst Port','?'),
        "protocol": row.get('Protocol','?'),
        "timestamp": row.get('Timestamp','?'),
        **features
    }
    log.info(f"Payload : {x}")
    return x
    return {"flow_id": flow_id, "features": features}


def send_flow(session: requests.Session, payload: dict[str, Any]) -> None:
    response = session.post(
        config.API_URL,
        json=payload,
        timeout=config.API_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    try:
        result = response.json()
        log.info(
            "Flow envoyé | id=%s | prédiction=%s",
            payload["flow_id"],
            result.get("prediction", "réponse reçue"),
        )
    except ValueError:
        log.info("Flow envoyé | id=%s | HTTP %s", payload["flow_id"], response.status_code)


def read_header(file_obj) -> list[str]:
    """
    Recherche la première ligne non vide du CSV et la lit comme en-tête.
    Retourne une liste vide si l'en-tête n'est pas encore disponible.
    """
    while True:
        position = file_obj.tell()
        header_bytes = file_obj.readline()

        if not header_bytes:
            return []

        # Ignorer les lignes vides ou composées uniquement d'espaces.
        if not header_bytes.strip():
            continue

        if not header_bytes.endswith(b"\n"):
            # La ligne est encore en cours d'écriture.
            file_obj.seek(position)
            return []

        header_text = header_bytes.decode("utf-8-sig").strip("\r\n")
        header = next(csv.reader([header_text]))

        # Nettoyer les noms des colonnes.
        header = [column.strip() for column in header]

        if header and any(header):
            return header


def watch(csv_path: Path, from_beginning: bool = False) -> None:
    log.info("CSV surveillé : %s", csv_path)
    log.info("API cible : %s", config.API_URL)
    log.info("Caractéristiques attendues : %d", len(MODEL_FEATURES))
    log.info("Mode initial : %s", "historique + nouveaux flows" if from_beginning else "nouveaux flows uniquement")

    session = requests.Session()
    session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})
    header: list[str] | None = None
    offset = 0

    while True:
        if not csv_path.exists():
            log.info("En attente du fichier CSV : %s", csv_path)
            time.sleep(config.POLL_INTERVAL_SECONDS)
            continue

        try:
            with csv_path.open("rb") as f:
                current_size = csv_path.stat().st_size

                if header is None:
                    header = read_header(f)
                    log.info("DEBUG HEADER : %r", header)
                    log.info("DEBUG NOMBRE DE COLONNES : %d", len(header))

                    if not header:
                        log.debug("En attente de l'en-tête CSV...")
                        time.sleep(config.POLL_INTERVAL_SECONDS)
                        continue

                    log.info("Header chargé : %d colonnes", len(header))

                    # Sécurité : l'en-tête doit être valide.
                    if len(header) != 84:
                        log.error(
                            "Nombre de colonnes inattendu dans l'en-tête : %d (84 attendues).",
                            len(header)
                        )
                        header = None
                        time.sleep(config.POLL_INTERVAL_SECONDS)
                        continue

                    offset = f.tell() if from_beginning else current_size

                    if not from_beginning:
                        log.info("Les anciennes lignes seront ignorées.")

                    log.info("Lecture du CSV initialisée.")
                    if not from_beginning:
                        log.info("Header lu ; les lignes antérieures au démarrage seront ignorées.")
                    log.info("Header chargé : %d colonnes", len(header))

                # Le fichier a pu être recréé/tronqué lors d'un nouveau lancement.
                if current_size < offset:
                    log.warning("CSV tronqué ou recréé : reprise depuis le début.")
                    header = None
                    offset = 0
                    continue

                f.seek(offset)
                while True:
                    row_start = f.tell()
                    raw_line = f.readline()
                    if not raw_line:
                        break

                    # Ignorer les lignes vides.
                    if not raw_line.strip():
                        offset = f.tell()
                        continue

                    if not raw_line.endswith(b"\n"):
                        f.seek(row_start)
                        break
                    if not raw_line:
                        break
                    if not raw_line.endswith(b"\n"):
                        # CICFlowMeter est encore en train d'écrire cette ligne.
                        f.seek(row_start)
                        break

                    try:
                        line = raw_line.decode("utf-8").strip("\r\n")
                        values = next(csv.reader([line]))
                        if len(values) != len(header):
                            raise ValueError(
                                f"Ligne CSV avec {len(values)} champs, header avec {len(header)}"
                            )
                        row = dict(zip(header, values))
                        payload = build_payload(row)

                    except Exception as exc:
                        log.error("Ligne CSV ignorée (offset %d) : %s", row_start, exc)
                        offset = f.tell()
                        continue

                    try:
                        send_flow(session, payload)
                        offset = f.tell()
                    except requests.RequestException as exc:
                        # Ne pas avancer l'offset : cette ligne sera retentée.
                        f.seek(row_start)
                        log.error("Échec API pour %s : %s", payload["flow_id"], exc)
                        log.info("Nouvelle tentative dans %.1f s ; la ligne reste en attente.", config.HTTP_RETRY_SECONDS)
                        time.sleep(config.HTTP_RETRY_SECONDS)
                        break

        except PermissionError:
            log.warning("CSV temporairement inaccessible (fichier utilisé par un autre processus).")
        except OSError as exc:
            log.error("Erreur de lecture CSV : %s", exc)

        time.sleep(config.POLL_INTERVAL_SECONDS)


def main() -> None:
    parser = argparse.ArgumentParser(description="Surveille live_flows.csv et envoie les flows à FastAPI.")
    parser.add_argument("--csv", type=Path, default=config.CSV_PATH, help="Chemin du CSV CICFlowMeter.")
    parser.add_argument(
        "--from-beginning",
        action="store_true",
        default=config.START_FROM_BEGINNING,
        help="Envoyer également les lignes déjà présentes dans le CSV.",
    )
    args = parser.parse_args()

    try:
        watch(args.csv.resolve(), from_beginning=args.from_beginning)
    except KeyboardInterrupt:
        log.info("Arrêt demandé. CSV Watcher arrêté proprement.")


if __name__ == "__main__":
    main()
