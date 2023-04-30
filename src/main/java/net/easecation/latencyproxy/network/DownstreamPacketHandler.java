package net.easecation.latencyproxy.network;

import com.nukkitx.protocol.bedrock.BedrockClientSession;
import com.nukkitx.protocol.bedrock.handler.BedrockPacketHandler;
import com.nukkitx.protocol.bedrock.packet.DisconnectPacket;
import com.nukkitx.protocol.bedrock.packet.NetworkStackLatencyPacket;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class DownstreamPacketHandler implements BedrockPacketHandler {
    private final BedrockClientSession downstream;
    private final ProxySession proxySession;

    @Override
    public boolean handle(DisconnectPacket packet) {
        downstream.disconnect();
        return false;
    }

    @Override
    public boolean handle(NetworkStackLatencyPacket packet) {
        if (packet.isFromServer()) {
            NetworkStackLatencyPacket pong = new NetworkStackLatencyPacket();
            pong.setFromServer(true);
            pong.setTimestamp(packet.getTimestamp());
            downstream.sendPacket(pong);
            return true;
        }

        proxySession.pongP2S();
        return true;
    }
}
