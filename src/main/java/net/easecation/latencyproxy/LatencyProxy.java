package net.easecation.latencyproxy;

import com.nukkitx.protocol.bedrock.BedrockClient;
import com.nukkitx.protocol.bedrock.BedrockPacketCodec;
import com.nukkitx.protocol.bedrock.BedrockServer;
import com.nukkitx.protocol.bedrock.v567.Bedrock_v567patch;
import io.netty.util.ResourceLeakDetector;
import lombok.Getter;
import lombok.extern.log4j.Log4j2;
import net.easecation.latencyproxy.network.ProxyBedrockEventHandler;
import net.easecation.latencyproxy.util.ProxyStatistics;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

@Log4j2
@Getter
public class LatencyProxy {
    public static final BedrockPacketCodec CODEC = Bedrock_v567patch.BEDROCK_V567PATCH.toBuilder()
            .protocolVersion(568)
            .minecraftVersion("1.19.63")
            .build();
    public static final int PROTOCOL_VERSION = CODEC.getProtocolVersion();
    public static final String MINECRAFT_VERSION = CODEC.getMinecraftVersion();

    private final AtomicBoolean running = new AtomicBoolean(true);
    private Configuration configuration;

    private InetSocketAddress targetAddress;
    private InetSocketAddress proxyAddress;
    private BedrockServer bedrockServer;
    private final Set<BedrockClient> clients = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public static void main(String[] args) {
        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.DISABLED);

        LatencyProxy proxy = new LatencyProxy();
        try {
            proxy.boot();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void boot() throws IOException {
        log.info("Loading configuration...");
        Path configPath = Paths.get(".").resolve("config.yml");
        if (Files.notExists(configPath) || !Files.isRegularFile(configPath)) {
            Files.copy(LatencyProxy.class.getClassLoader().getResourceAsStream("config.yml"), configPath, StandardCopyOption.REPLACE_EXISTING);
        }

        configuration = Configuration.load(configPath);

        proxyAddress = configuration.getProxy().getAddress();
        targetAddress = configuration.getDestination().getAddress();

        log.info("Loading server...");
        BedrockServer bedrockServer = new BedrockServer(proxyAddress);
        bedrockServer.setHandler(new ProxyBedrockEventHandler(this));
        bedrockServer.bind().join();
        this.bedrockServer = bedrockServer;
        log.info("RakNet server started on {}", proxyAddress);

        ProxyStatistics.registerJmxMonitoring();

        Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown, "Shutdown Hook"));

        loop();
    }

    public BedrockClient newClient() {
        BedrockClient client = new BedrockClient(new InetSocketAddress(0));
        clients.add(client);
        client.bind().join();
        return client;
    }

    private void loop() {
        while (running.get()) {
            try {
                synchronized (this) {
                    wait();
                }
            } catch (InterruptedException ignored) {
            }
        }

        clients.forEach(BedrockClient::close);
        bedrockServer.close();
    }

    public void shutdown() {
        if (running.compareAndSet(true, false)) {
            synchronized (this) {
                notify();
            }
        }
    }

    public boolean canAcceptConnectionRequest() {
        return clients.isEmpty();
    }
}
