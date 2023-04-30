package net.easecation.latencyproxy.network;

import com.nukkitx.protocol.bedrock.BedrockPong;
import com.nukkitx.protocol.bedrock.BedrockServerEventHandler;
import com.nukkitx.protocol.bedrock.BedrockServerSession;
import net.easecation.latencyproxy.LatencyProxy;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import java.net.InetSocketAddress;

@ParametersAreNonnullByDefault
public class ProxyBedrockEventHandler implements BedrockServerEventHandler {
    private static final BedrockPong ADVERTISEMENT = new BedrockPong();

    private final LatencyProxy proxy;

    public ProxyBedrockEventHandler(LatencyProxy proxy) {
        this.proxy = proxy;
        int port = proxy.getProxyAddress().getPort();
        ADVERTISEMENT.setIpv4Port(port);
        ADVERTISEMENT.setIpv6Port(port);
    }

    @Override
    public boolean onConnectionRequest(InetSocketAddress address) {
        return proxy.canAcceptConnectionRequest();
    }

    @Nonnull
    public BedrockPong onQuery(InetSocketAddress address) {
        return ADVERTISEMENT;
    }

    @Override
    public void onSessionCreation(BedrockServerSession session) {
        session.setPacketHandler(new UpstreamPacketHandler(session, proxy));
    }

    static {
        ADVERTISEMENT.setEdition("MCPE");
        ADVERTISEMENT.setGameType("Survival");
        ADVERTISEMENT.setVersion(LatencyProxy.MINECRAFT_VERSION);
        ADVERTISEMENT.setProtocolVersion(LatencyProxy.PROTOCOL_VERSION);
        ADVERTISEMENT.setMotd("Latency Test");
        ADVERTISEMENT.setSubMotd("Proxy");
        ADVERTISEMENT.setMaximumPlayerCount(1);
        ADVERTISEMENT.setPlayerCount(0);
    }
}
