# Modifications apportées

1. Remplacement du fichier `LiveCaptureCli.java` qui contenait seulement un fragment d'exemple par une classe Java complète.
2. Ajout de l'énumération des interfaces (`--list-interfaces`) via `Pcap.findAllDevs`.
3. Ajout de la capture live via `Pcap.openLive` et `pcap.loop`, avec copie des paquets avant décodage.
4. Réutilisation de `PacketReader.getBasicPacketInfo` et `FlowGenerator`.
5. Ajout d'un writer CSV continu : en-tête unique, ajout d'une ligne par flow et flush immédiat.
6. Gestion de `Ctrl+C`, fermeture des ressources et export des flows encore actifs.
7. Correction du test des deux drapeaux FIN TCP dans `FlowGenerator`.
8. Ajout de la documentation et du fragment Gradle nécessaire.

Le `build.gradle`, les JAR et les DLL ne figuraient pas dans l'archive source fournie. Ils n'ont donc pas été modifiés ni inclus. Il faut ajouter la tâche `executeLive` du fichier `BUILD_GRADLE_TASK_LIVE.txt` dans le `build.gradle` du dépôt complet.
