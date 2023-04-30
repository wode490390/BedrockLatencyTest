package net.easecation.latencyproxy.network;

import com.nukkitx.protocol.bedrock.BedrockPacket;
import com.nukkitx.protocol.bedrock.BedrockSession;
import com.nukkitx.protocol.bedrock.handler.BatchHandler;
import com.nukkitx.protocol.bedrock.handler.BedrockPacketHandler;
import io.netty.buffer.ByteBuf;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class ProxyBatchHandler implements BatchHandler {
    private final BedrockSession session;

    public ProxyBatchHandler(BedrockSession session) {
        this.session = session;
    }

    @Override
    public void handle(BedrockSession session, ByteBuf compressed, Collection<BedrockPacket> packets) {
        boolean batchHandled = false;
        List<BedrockPacket> unhandled = new ArrayList<>(packets.size());

        for (BedrockPacket packet : packets) {
            BedrockPacketHandler handler = session.getPacketHandler();
            if (handler != null && packet.handle(handler)) {
                batchHandled = true;
            } else {
                unhandled.add(packet);
            }
        }

        if (!batchHandled) {
            compressed.resetReaderIndex();
            this.session.sendWrapped(compressed, true);
        } else if (!unhandled.isEmpty()) {
            this.session.sendWrapped(unhandled, true);
        }
    }
}
