package net.easecation.latencyproxy.network;

import com.nukkitx.network.util.DisconnectReason;
import com.nukkitx.protocol.bedrock.BedrockClientSession;
import com.nukkitx.protocol.bedrock.BedrockServerSession;
import com.nukkitx.protocol.bedrock.handler.BatchHandler;
import com.nukkitx.protocol.bedrock.packet.NetworkStackLatencyPacket;
import com.nukkitx.protocol.bedrock.util.EncryptionUtils;
import lombok.AccessLevel;
import lombok.Getter;

import java.security.KeyPair;

@Getter
public class ProxySession {
    private final BedrockServerSession upstream;
    private final BedrockClientSession downstream;
    @Getter(AccessLevel.PACKAGE)
    private final KeyPair proxyKeyPair = EncryptionUtils.createKeyPair();

    public long pingC2P;
    public long pingP2S;
    public static long latencyC2P;
    public static long latencyP2S;

    public ProxySession(BedrockServerSession upstream, BedrockClientSession downstream) {
        this.upstream = upstream;
        this.downstream = downstream;
        this.upstream.addDisconnectHandler(reason -> {
            if (reason != DisconnectReason.DISCONNECTED) {
                this.downstream.disconnect();
            }
        });
    }

    public BatchHandler createUpstreamBatchHandler() {
        return new ProxyBatchHandler(downstream);
    }

    public BatchHandler createDownstreamTailHandler() {
        return new ProxyBatchHandler(upstream);
    }

    public void pingC2P() {
        NetworkStackLatencyPacket ping = new NetworkStackLatencyPacket();
        ping.setFromServer(true);
        long time = System.nanoTime();
        pingC2P = time;
        ping.setTimestamp(time);
        upstream.sendPacket(ping);
    }

    public void pongC2P() {
        latencyC2P = System.nanoTime() - pingC2P;
        pingC2P();
    }

    public void pingP2S() {
        NetworkStackLatencyPacket ping = new NetworkStackLatencyPacket();
        ping.setFromServer(false);
        long time = System.nanoTime();
        pingP2S = time;
        ping.setTimestamp(time);
        downstream.sendPacket(ping);
    }

    public void pongP2S() {
        latencyP2S = System.nanoTime() - pingP2S;
        pingP2S();
    }
}
