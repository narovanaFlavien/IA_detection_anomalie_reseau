package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.jnetpcap.BasicFlow;
import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import cic.cs.unb.ca.jnetpcap.FlowFeature;
import cic.cs.unb.ca.jnetpcap.FlowGenerator;
import cic.cs.unb.ca.jnetpcap.PacketReader;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Command-line live capture entry point.
 *
 * Examples:
 *   gradlew.bat executeLive -PlistInterfaces
 *   gradlew.bat executeLive -Piface="Wi-Fi" -Poutput="data/live_flows.csv"
 *
 * This class reuses the same packet decoding and flow-generation code as
 * TrafficFlowWorker, but does not depend on Swing.
 */
public final class LiveCaptureCli {

    private static final int DEFAULT_SNAPLEN = 64 * 1024;
    private static final int DEFAULT_READ_TIMEOUT_MS = 1000;
    private static final long DEFAULT_FLOW_TIMEOUT_US = 120000000L;
    private static final long DEFAULT_ACTIVITY_TIMEOUT_US = 5000000L;

    private LiveCaptureCli() {
    }

    public static void main(String[] args) {
        try {
            Options options = Options.parse(args);

            if (options.help) {
                printUsage();
                return;
            }

            if (options.listInterfaces) {
                listInterfaces();
                return;
            }

            if (options.interfaceName == null || options.interfaceName.trim().isEmpty()) {
                System.err.println("Erreur : indique une interface avec --interface.");
                printUsage();
                System.exit(2);
            }

            if (options.output == null || options.output.trim().isEmpty()) {
                System.err.println("Erreur : indique un CSV avec --output.");
                printUsage();
                System.exit(2);
            }

            capture(options);
        } catch (IllegalArgumentException e) {
            System.err.println("Erreur : " + e.getMessage());
            printUsage();
            System.exit(2);
        } catch (Exception e) {
            System.err.println("Erreur pendant la capture : " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static void listInterfaces() {
        StringBuilder errbuf = new StringBuilder();
        List<PcapIf> devices = new ArrayList<PcapIf>();

        int result = Pcap.findAllDevs(devices, errbuf);
        if (result != Pcap.OK) {
            throw new IllegalStateException("Impossible de lister les interfaces : " + errbuf);
        }

        if (devices.isEmpty()) {
            System.out.println("Aucune interface réseau trouvée. Vérifie Npcap et ses permissions.");
            return;
        }

        System.out.println("Interfaces réseau disponibles :");
        for (int i = 0; i < devices.size(); i++) {
            PcapIf device = devices.get(i);
            String description = device.getDescription() == null
                    ? "(sans description)" : device.getDescription();
            System.out.println("[" + i + "] " + device.getName() + " - " + description);
        }
        System.out.println();
        System.out.println("Utilise le nom exact de l'interface avec --interface.");
    }

    private static PcapIf resolveInterface(String requestedName) {
        StringBuilder errbuf = new StringBuilder();
        List<PcapIf> devices = new ArrayList<PcapIf>();

        if (Pcap.findAllDevs(devices, errbuf) != Pcap.OK) {
            throw new IllegalStateException("Impossible de lister les interfaces : " + errbuf);
        }

        // Accept either an exact interface name or its numeric index.
        try {
            int index = Integer.parseInt(requestedName);
            if (index >= 0 && index < devices.size()) {
                return devices.get(index);
            }
            throw new IllegalArgumentException("Index d'interface invalide : " + index);
        } catch (NumberFormatException ignored) {
            // The argument is an interface name.
        }

        for (PcapIf device : devices) {
            if (device.getName().equals(requestedName)) {
                return device;
            }
        }

        StringBuilder available = new StringBuilder();
        for (int i = 0; i < devices.size(); i++) {
            if (i > 0) {
                available.append(", ");
            }
            available.append(i).append(": ").append(devices.get(i).getName());
        }
        throw new IllegalArgumentException(
                "Interface introuvable : " + requestedName + ". Interfaces disponibles : " + available);
    }

    private static void capture(final Options options) throws IOException {
        final PcapIf device = resolveInterface(options.interfaceName);
        final CsvFlowWriter csvWriter = new CsvFlowWriter(
                Paths.get(options.output), options.append);

        final FlowGenerator flowGenerator = new FlowGenerator(
                true, options.flowTimeoutUs, options.activityTimeoutUs);
        flowGenerator.addFlowListener(csvWriter);

        StringBuilder errbuf = new StringBuilder();
        int promiscuousMode = options.promiscuous ? Pcap.MODE_PROMISCUOUS : 0;

        final Pcap pcap = Pcap.openLive(
                device.getName(),
                options.snaplen,
                promiscuousMode,
                options.readTimeoutMs,
                errbuf);

        if (pcap == null) {
            csvWriter.close();
            throw new IllegalStateException(
                    "Impossible d'ouvrir l'interface " + device.getName() + " : " + errbuf);
        }

        final AtomicLong totalPackets = new AtomicLong(0);
        final AtomicLong validPackets = new AtomicLong(0);

        // Ctrl+C asks libpcap to leave its blocking capture loop. Cleanup is
        // performed by the main thread in the finally block below.
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                pcap.breakloop();
            }
        }, "cicflowmeter-live-shutdown"));

        System.out.println("CICFlowMeter Live démarré.");
        System.out.println("Interface : " + device.getName());
        System.out.println("CSV       : " + Paths.get(options.output).toAbsolutePath());
        System.out.println("IPv4      : activé");
        System.out.println("IPv6      : " + (options.ipv6 ? "activé" : "désactivé"));
        System.out.println("Mode promiscuité : " + (options.promiscuous ? "activé" : "désactivé"));
        System.out.println("Appuie sur Ctrl+C pour arrêter proprement.");
        System.out.println();

        PcapPacketHandler<String> packetHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                totalPackets.incrementAndGet();

                try {
                    // jNetPcap reuses native packet buffers. Make a copy before
                    // passing the packet to the feature extractor.
                    PcapPacket permanent = new PcapPacket(Type.POINTER);
                    packet.transferStateAndDataTo(permanent);

                    BasicPacketInfo packetInfo = PacketReader.getBasicPacketInfo(
                            permanent, true, options.ipv6);

                    if (packetInfo != null) {
                        flowGenerator.addPacket(packetInfo);
                        validPackets.incrementAndGet();
                    }
                } catch (RuntimeException e) {
                    System.err.println("Paquet ignoré (erreur de décodage) : " + e.getMessage());
                }
            }
        };

        int captureResult = -1;
        try {
            captureResult = pcap.loop(Pcap.DISPATCH_BUFFER_FULL, packetHandler, device.getName());
        } finally {
            // Emit flows that were still open when capture stopped.
            flowGenerator.flushCurrentFlows();

            try {
                csvWriter.close();
            } finally {
                pcap.close();
            }
        }

        System.out.println();
        System.out.println("Capture terminée.");
        System.out.println("Paquets reçus       : " + totalPackets.get());
        System.out.println("Paquets décodés     : " + validPackets.get());
        System.out.println("Flows écrits dans le CSV : " + csvWriter.getWrittenFlows());
        System.out.println("Code de fin libpcap : " + captureResult);

        if (csvWriter.getFailure() != null) {
            throw new IOException("Erreur d'écriture CSV", csvWriter.getFailure());
        }
        if (captureResult == -1) {
            throw new IllegalStateException("Erreur libpcap pendant la capture.");
        }
    }

    private static void printUsage() {
        System.out.println();
        System.out.println("CICFlowMeter - capture réseau en temps réel");
        System.out.println();
        System.out.println("Lister les interfaces :");
        System.out.println("  --list-interfaces");
        System.out.println();
        System.out.println("Démarrer une capture :");
        System.out.println("  --interface <nom-ou-index> --output <fichier.csv> [options]");
        System.out.println();
        System.out.println("Options :");
        System.out.println("  --append                    Ajoute les flows à un CSV existant");
        System.out.println("  --no-promiscuous            Désactive le mode promiscuous");
        System.out.println("  --no-ipv6                   Ignore IPv6 (IPv4 reste activé)");
        System.out.println("  --snaplen <octets>          Taille maximale capturée (défaut : 65536)");
        System.out.println("  --read-timeout <ms>         Timeout de lecture (défaut : 1000)");
        System.out.println("  --flow-timeout <microsec>   Timeout global (défaut : 120000000)");
        System.out.println("  --activity-timeout <us>     Timeout d'activité (défaut : 5000000)");
        System.out.println("  --help                      Affiche cette aide");
        System.out.println();
        System.out.println("Exemple :");
        System.out.println("  --interface \"Wi-Fi\" --output \"data/live_flows.csv\"");
    }

    /**
     * Writes completed flows incrementally. Each row is flushed so a separate
     * Python tailer can read it without waiting for the Java process to stop.
     */
    private static final class CsvFlowWriter implements FlowGenListener, AutoCloseable {
        private final BufferedWriter writer;
        private final AtomicLong writtenFlows = new AtomicLong(0);
        private volatile IOException failure;

        CsvFlowWriter(Path output, boolean append) throws IOException {
            Path absolute = output.toAbsolutePath();
            Path parent = absolute.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }

            boolean needsHeader = !Files.exists(absolute) || Files.size(absolute) == 0L;

            if (append) {
                writer = Files.newBufferedWriter(
                        absolute,
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.WRITE,
                        StandardOpenOption.APPEND);
            } else {
                writer = Files.newBufferedWriter(
                        absolute,
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.WRITE,
                        StandardOpenOption.TRUNCATE_EXISTING);
                needsHeader = true;
            }

            if (needsHeader) {
                writer.write(FlowFeature.getHeader());
                writer.newLine();
                writer.flush();
            }
        }

        @Override
        public synchronized void onFlowGenerated(BasicFlow flow) {
            if (flow == null || flow.packetCount() <= 1 || failure != null) {
                return;
            }

            try {
                writer.write(flow.dumpFlowBasedFeaturesEx());
                writer.newLine();
                writer.flush();
                writtenFlows.incrementAndGet();
            } catch (IOException e) {
                failure = e;
                System.err.println("Erreur d'écriture dans le CSV : " + e.getMessage());
            }
        }

        long getWrittenFlows() {
            return writtenFlows.get();
        }

        IOException getFailure() {
            return failure;
        }

        @Override
        public synchronized void close() throws IOException {
            writer.flush();
            writer.close();
        }
    }

    private static final class Options {
        String interfaceName;
        String output;
        boolean listInterfaces;
        boolean help;
        boolean append;
        boolean promiscuous = true;
        boolean ipv6 = true;
        int snaplen = DEFAULT_SNAPLEN;
        int readTimeoutMs = DEFAULT_READ_TIMEOUT_MS;
        long flowTimeoutUs = DEFAULT_FLOW_TIMEOUT_US;
        long activityTimeoutUs = DEFAULT_ACTIVITY_TIMEOUT_US;

        static Options parse(String[] args) {
            Options options = new Options();

            for (int i = 0; i < args.length; i++) {
                String arg = args[i];

                if ("--help".equals(arg) || "-h".equals(arg)) {
                    options.help = true;
                } else if ("--list-interfaces".equals(arg)) {
                    options.listInterfaces = true;
                } else if ("--append".equals(arg)) {
                    options.append = true;
                } else if ("--no-promiscuous".equals(arg)) {
                    options.promiscuous = false;
                } else if ("--no-ipv6".equals(arg)) {
                    options.ipv6 = false;
                } else if ("--interface".equals(arg)) {
                    options.interfaceName = requireValue(args, ++i, arg);
                } else if ("--output".equals(arg)) {
                    options.output = requireValue(args, ++i, arg);
                } else if ("--snaplen".equals(arg)) {
                    options.snaplen = parseInt(requireValue(args, ++i, arg), arg);
                } else if ("--read-timeout".equals(arg)) {
                    options.readTimeoutMs = parseInt(requireValue(args, ++i, arg), arg);
                } else if ("--flow-timeout".equals(arg)) {
                    options.flowTimeoutUs = parseLong(requireValue(args, ++i, arg), arg);
                } else if ("--activity-timeout".equals(arg)) {
                    options.activityTimeoutUs = parseLong(requireValue(args, ++i, arg), arg);
                } else {
                    throw new IllegalArgumentException("Option inconnue : " + arg);
                }
            }

            if (options.snaplen <= 0 || options.readTimeoutMs < 0
                    || options.flowTimeoutUs <= 0 || options.activityTimeoutUs < 0) {
                throw new IllegalArgumentException("Les valeurs numériques des options doivent être positives (timeout de lecture peut être zéro).");
            }

            return options;
        }

        private static String requireValue(String[] args, int index, String option) {
            if (index >= args.length || args[index].startsWith("--")) {
                throw new IllegalArgumentException("Valeur manquante pour " + option);
            }
            return args[index];
        }

        private static int parseInt(String value, String option) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Valeur entière invalide pour " + option + " : " + value);
            }
        }

        private static long parseLong(String value, String option) {
            try {
                return Long.parseLong(value);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Valeur numérique invalide pour " + option + " : " + value);
            }
        }
    }
}
