# Collector réseau — CICFlowMeter Live + CSV Watcher

Ce dossier fournit deux processus indépendants :

1. `collector.capture` lance le `LiveCaptureCli` Java déjà ajouté au projet CICFlowMeter.
2. `collector.csv_watcher` surveille le CSV et envoie chaque flow terminé à FastAPI.

Le watcher ne capture pas lui-même les paquets. Il lit les lignes CSV produites par CICFlowMeter.

## 1. Architecture

```text
Interface réseau (Windows / Npcap)
              |
              v
   CICFlowMeter LiveCaptureCli
              |
              v
       data/live_flows.csv
              |
              v
   collector/csv_watcher.py
              |
       HTTP POST JSON
              |
              v
   FastAPI : POST /api/flows/predict
              |
              v
      Extra Trees (70 features)
```

Les deux processus restent indépendants de FastAPI. La capture ne bloque donc pas les routes HTTP.

## 2. Structure

```text
project-root/
├── backend/
├── frontend/
├── collector/
│   ├── __init__.py
│   ├── config.py
│   ├── capture.py
│   ├── csv_watcher.py
│   └── feature_mapping.json
├── data/
│   └── live_flows.csv
├── .env
├── requirements.txt
├── run_capture.bat
├── run_watcher.bat
└── run_all.bat
```

Le dossier `collector/` de cette archive doit être copié à la racine du projet. Les fichiers `.bat`, `.env.example` et `requirements.txt` sont également à copier à la racine.

## 3. Prérequis

- Windows avec Python 3.10 ou plus récent.
- Le projet CICFlowMeter modifié, avec `gradlew.bat`, `build.gradle` et la classe `LiveCaptureCli`.
- Java/JDK, Gradle wrapper et Npcap déjà opérationnels.
- FastAPI démarré et accessible depuis le PC.
- L'endpoint `POST /api/flows/predict` doit accepter le JSON décrit plus bas.

Installer les dépendances Python depuis la racine :

```bat
py -m venv .venv
.venv\Scripts\activate
py -m pip install -r requirements.txt
```

Copier `.env.example` vers `.env`, puis adapter les chemins et l'URL. Le fichier `.env` est chargé automatiquement par `collector.config` grâce à `python-dotenv`.

### Configuration importante

`CICFLOWMETER_DIR` doit désigner le dossier qui contient `gradlew.bat`.

Exemple :

```env
CICFLOWMETER_DIR=C:\dev\CICFlowMeter
CSV_PATH=C:\dev\network-anomaly-detection\data\live_flows.csv
API_URL=http://127.0.0.1:8000/api/flows/predict
NETWORK_INTERFACE=7
```

Les chemins relatifs sont résolus depuis la racine du projet qui contient `collector/`.

## 4. Démarrage conseillé

D'abord, démarrer FastAPI dans son terminal habituel, par exemple :

```bat
cd backend
uvicorn app.main:app --reload
```

Adaptez cette commande à votre vrai module FastAPI.

Ensuite, à la racine du projet :

**Option A — lancer les deux processus automatiquement**

```bat
run_all.bat
```

Deux fenêtres s'ouvrent : CSV Watcher et CICFlowMeter Live Capture. Le watcher démarre en premier.

**Option B — démarrer séparément**

Terminal 1 :

```bat
run_watcher.bat
```

Terminal 2 :

```bat
run_capture.bat
```

Pour arrêter, faites `Ctrl+C` dans la fenêtre de capture. Le watcher peut ensuite être arrêté avec `Ctrl+C` ou en fermant sa fenêtre.

## 5. Contrat HTTP utilisé

Pour chaque ligne CSV complète, le watcher envoie :

```json
{
  "flow_id": "192.168.41.173-3.173.21.63-10291-443-6",
  "features": {
    "Destination Port": 443,
    "Flow Duration": 551822,
    "Total Fwd Packets": 6
  }
}
```

L'exemple est raccourci : `features` contient en réalité les **70 caractéristiques** et leurs noms exacts provenant de `supervised_v1_features.json`.

L'endpoint attendu est :

```http
POST /api/flows/predict
Content-Type: application/json
```

Le format reprend le contrat indiqué dans le document d'architecture FastAPI/CICFlowMeter. Le watcher attend une réponse JSON facultative contenant `prediction` pour l'afficher dans le terminal.

Si ton endpoint réel utilise un autre chemin ou un autre schéma Pydantic, change `API_URL` ou adapte `send_flow()` dans `csv_watcher.py`.

## 6. Correspondance des colonnes CSV et du modèle

Le CSV réel fourni contient 84 colonnes, tandis que le modèle `supervised_v1` en attend 70. Il ne faut donc pas transmettre les 84 colonnes directement.

`feature_mapping.json` contient la liste ordonnée des 70 features et les alias de CICFlowMeter. Par exemple :

| Feature attendue par le modèle | Colonne CICFlowMeter |
|---|---|
| `Destination Port` | `Dst Port` |
| `Total Fwd Packets` | `Total Fwd Packet` |
| `Total Backward Packets` | `Total Bwd packets` |
| `Min Packet Length` | `Packet Length Min` |
| `CWE Flag Count` | `CWR Flag Count` |
| `Init_Win_bytes_forward` | `FWD Init Win Bytes` |

Le watcher construit le dictionnaire dans l'ordre exact de `supervised_v1_features.json`. Il ignore les colonnes de contexte (`Flow ID`, IP, timestamp, `Label`) qui ne font pas partie des 70 features.

**Point de vigilance :** `Fwd Header Length.1` du modèle est associé à `Fwd Header Length` du CSV, car le CSV live ne contient qu'une seule colonne portant cette mesure. Cette correspondance doit être confirmée en comparant la définition des données d'entraînement avec CICFlowMeter. La syntaxe et la présence des colonnes ont été vérifiées sur le CSV fourni, mais cela ne prouve pas à lui seul l'équivalence statistique des distributions.

## 7. Comportement du watcher

- Lit uniquement les lignes terminées par `\\n` : une ligne en cours d'écriture n'est pas envoyée.
- Par défaut, ignore l'historique déjà présent et traite seulement les nouveaux flows ajoutés après le démarrage.
- `--from-beginning` permet de traiter également les lignes déjà présentes.
- Si FastAPI est indisponible, le watcher conserve l'offset de la ligne et réessaie ; il ne passe pas à la ligne suivante.
- Si une ligne est mal formée ou si une feature manque/n'est pas numérique, elle est signalée et ignorée.
- Si le CSV est tronqué/recréé, le watcher relit son header.
- Les valeurs `NaN` et infinies sont refusées au lieu d'être transformées silencieusement.

Commandes utiles :

```bat
python -m collector.csv_watcher --from-beginning
python -m collector.csv_watcher --csv "C:\chemin\live_flows.csv"
python -m collector.capture --interface 7
python -m collector.capture --interface "Wi-Fi" --output "data\test.csv"
```

## 8. Limites et prochaine validation

1. Le watcher transmet un flow après que CICFlowMeter l'a clôturé et écrit sa ligne. Il ne prédit pas à chaque paquet : un délai est donc normal.
2. Le watcher fait actuellement un POST par flow. Pour un débit élevé, on pourra ajouter un endpoint batch et envoyer plusieurs flows par requête.
3. L'offset n'est pas encore sauvegardé sur disque : si le watcher est arrêté puis redémarré, il ignorera l'historique par défaut. Les flows en attente au moment de l'arrêt devront être retraités avec `--from-beginning` ou via une future persistance d'offset.
4. Vérifier que l'API utilise exactement les mêmes noms de features, les mêmes unités et le même ordre que le pipeline entraîné.
5. Tester d'abord avec un petit nombre de flows et comparer une prédiction hors-ligne avec la prédiction FastAPI pour le même flow.
6. Capturer uniquement un réseau pour lequel vous avez l'autorisation de surveillance.

## 9. Test de correspondance CSV

Le fichier `feature_mapping.json` est construit à partir du fichier `supervised_v1_features.json` fourni dans le projet. La validation effectuée sur `live_flows.csv` a confirmé que chaque feature attendue possède une colonne source ou un alias. Le fichier CSV exemple contenait 26 lignes et le label `NeedManualLabel` ; ce label est ignoré, car il ne s'agit pas d'une vérité terrain ni d'une entrée du modèle.
