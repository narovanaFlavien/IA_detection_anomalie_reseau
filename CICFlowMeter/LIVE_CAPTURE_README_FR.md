# Adaptation CICFlowMeter Java - Capture Live en CLI

Cette adaptation ajoute une entrée en ligne de commande pour capturer directement une interface réseau avec jNetPcap/Npcap, construire les flows avec le `FlowGenerator` existant et écrire progressivement les flows terminés dans un CSV.

## Contenu modifié

- `src/main/java/cic/cs/unb/ca/ifm/LiveCaptureCli.java` : nouvelle commande CLI, sans dépendance Swing.
- `src/main/java/cic/cs/unb/ca/jnetpcap/FlowGenerator.java` :
  - finalisation des flows encore actifs à l'arrêt de la capture ;
  - correction du test de fermeture TCP par double FIN (comparaison FIN avant + FIN arrière).

Les classes `PacketReader`, `BasicFlow`, `TrafficFlowWorker` et `Cmd` sont conservées. La capture Live réutilise la même conversion des paquets et le même moteur de flows que le mode graphique.

## Prérequis Windows

1. JDK 8 x64 (le projet source cible Java 8).
2. Npcap installé, avec l'option de compatibilité WinPcap API si elle est proposée.
3. Le JAR jNetPcap et les DLL natives du dépôt, notamment :
   `jnetpcap/win/jnetpcap-1.4.r1425`
4. Les dépendances Gradle/Maven déjà configurées dans le projet original.

Lancer le terminal en administrateur si Windows/Npcap refuse l'accès à l'interface. Ne lance pas le backend FastAPI avec des privilèges administrateur uniquement pour cette raison : seul le processus de capture en a éventuellement besoin.

## Ajouter la tâche Gradle

L'archive reçue ne contenait que `src/`, pas `build.gradle`. Ajoute donc cette tâche à la fin du `build.gradle` du projet original (en conservant les tâches existantes) :

```groovy
task executeLive(type: JavaExec) {
    main = 'cic.cs.unb.ca.ifm.LiveCaptureCli'
    classpath = sourceSets.main.runtimeClasspath

    // Emplacement des DLL natives jNetPcap sous Windows.
    systemProperty 'java.library.path',
            file('jnetpcap/win/jnetpcap-1.4.r1425').absolutePath

    if (project.hasProperty('listInterfaces')) {
        args '--list-interfaces'
    }

    if (project.hasProperty('iface')) {
        args '--interface', project.property('iface').toString()
    }

    if (project.hasProperty('output')) {
        args '--output', project.property('output').toString()
    }

    if (project.hasProperty('append')) {
        args '--append'
    }
}
```

Si le dépôt utilise un chemin différent pour les DLL, adapte uniquement le chemin `java.library.path` en reprenant celui de la tâche `exeCMD` existante.

## Compilation et vérification

Dans CMD, à la racine du dépôt :

```cmd
gradlew.bat clean classes
```

Lister les interfaces :

```cmd
gradlew.bat executeLive -PlistInterfaces
```

Démarrer une capture sur la première interface listée (exemple avec l'index 0) :

```cmd
gradlew.bat executeLive -Piface=0 -Poutput="data/live_flows.csv"
```

Tu peux aussi utiliser le nom exact affiché :

```cmd
gradlew.bat executeLive -Piface="Wi-Fi" -Poutput="data/live_flows.csv"
```

Arrêter avec `Ctrl+C`. Les flows encore actifs sont alors écrits comme flows partiels avant fermeture du CSV.

Pour ajouter les flows à un CSV déjà existant, ajoute `-Pappend` :

```cmd
gradlew.bat executeLive -Piface=0 -Poutput="data/live_flows.csv" -Pappend
```

Attention : en mode append, le fichier doit avoir le même format et le même en-tête que la capture courante.

## Options de la classe Java

Si tu l'exécutes directement depuis ton IDE, les arguments disponibles sont :

```text
--list-interfaces
--interface <nom-ou-index>
--output <fichier.csv>
--append
--no-promiscuous
--no-ipv6
--snaplen <octets>
--read-timeout <ms>
--flow-timeout <microsecondes>
--activity-timeout <microsecondes>
--help
```

## Comment fonctionne le CSV

- Le fichier est créé au démarrage.
- L'en-tête est écrit une seule fois.
- Chaque flow que le moteur déclare terminé est ajouté à la fin du CSV.
- Le writer effectue un `flush()` après chaque flow afin que le lecteur Python puisse voir rapidement les nouvelles lignes.
- À `Ctrl+C`, les flows toujours présents dans `currentFlows` et contenant plus d'un paquet sont exportés comme flows partiels.

Le CSV produit conserve le schéma `FlowFeature.getHeader()` et les valeurs de `BasicFlow.dumpFlowBasedFeaturesEx()` de cette version du dépôt.

## Limites et validations indispensables

1. **Compatibilité du modèle IA :** ce CSV contient le schéma CICFlowMeter de cette version. Il faut vérifier les noms, unités, calculs et ordre des 70 caractéristiques attendues par le pipeline Extra Trees avant de l'utiliser pour prédire.
2. **IPv4/IPv6 :** IPv4 et IPv6 sont activés par défaut dans la nouvelle CLI. Le décodage dépend toutefois des protocoles supportés par `PacketReader`.
3. **Timeouts :** les valeurs par défaut sont celles utilisées par `TrafficFlowWorker` (`120000000` et `5000000`, en microsecondes dans cette implémentation).
4. **Flows partiels :** les flows ouverts au moment de l'arrêt sont exportés avec les statistiques disponibles jusque-là. Ils ne sont pas équivalents à des flows naturellement terminés.
5. **Expiration en silence :** le `FlowGenerator` existant applique principalement ses vérifications de timeout à l'arrivée d'un paquet. Pour des réseaux très silencieux ou une surveillance longue durée, un mécanisme périodique d'expiration des flows inactifs pourra être ajouté ensuite.
6. **Tests :** commencer par une capture courte sur une machine et un réseau que tu es autorisé à surveiller, puis comparer un petit échantillon avec un PCAP traité par la commande offline.

## Architecture obtenue

```text
Interface réseau
      |
      v
jNetPcap / Npcap (openLive)
      |
      v
PacketReader.getBasicPacketInfo(...)
      |
      v
FlowGenerator.addPacket(...)
      |
      v
FlowGenListener.onFlowGenerated(...)
      |
      v
data/live_flows.csv
      |
      v
Python CSV watcher
      |
      v
FastAPI -> Extra Trees -> stockage / React
```
