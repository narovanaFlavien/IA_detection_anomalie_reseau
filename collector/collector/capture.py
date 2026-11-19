"""Lance le LiveCaptureCli Java depuis le dossier CICFlowMeter."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from . import config


def main() -> None:
    parser = argparse.ArgumentParser(description="Démarre la capture live CICFlowMeter.")
    parser.add_argument("--interface", default=config.NETWORK_INTERFACE, help="Index ou nom de l'interface réseau.")
    parser.add_argument("--output", type=Path, default=config.CSV_PATH, help="Chemin du CSV de sortie.")
    parser.add_argument("--append", action="store_true", default=config.APPEND_CSV, help="Ajouter au CSV existant.")
    args = parser.parse_args()

    cfm_dir = config.CICFLOWMETER_DIR
    gradlew = cfm_dir / "gradlew.bat"
    if not gradlew.exists():
        raise SystemExit(
            f"gradlew.bat introuvable dans : {cfm_dir}\n"
            "Définissez CICFLOWMETER_DIR dans collector/.env avec le chemin du projet CICFlowMeter."
        )

    output = args.output.expanduser()
    if not output.is_absolute():
        output = (config.PROJECT_ROOT / output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    command = [
        str(gradlew),
        "executeLive",
        f"-Piface={args.interface}",
        f"-Poutput={output}",
    ]
    if args.append:
        command.append("-Pappend")

    print("Dossier CICFlowMeter :", cfm_dir)
    print("Interface réseau    :", args.interface)
    print("CSV de sortie       :", output)
    print("\nCommande :", " ".join(f'"{part}"' if " " in part else part for part in command))
    print("\nLa capture démarre. Appuyez sur Ctrl+C pour l'arrêter.\n")

    try:
        # shell=True est nécessaire pour exécuter un .bat sous Windows.
        subprocess.run(subprocess.list2cmdline(command), cwd=cfm_dir, check=False, shell=True)
    except KeyboardInterrupt:
        print("\nArrêt demandé. Vérifiez que le processus Java s'est bien arrêté.")
    except FileNotFoundError as exc:
        raise SystemExit(f"Impossible de lancer Gradle : {exc}") from exc


if __name__ == "__main__":
    main()
