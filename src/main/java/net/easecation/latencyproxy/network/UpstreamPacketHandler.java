package net.easecation.latencyproxy.network;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.google.common.base.Preconditions;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nukkitx.protocol.bedrock.BedrockClient;
import com.nukkitx.protocol.bedrock.BedrockServerSession;
import com.nukkitx.protocol.bedrock.data.PacketCompressionAlgorithm;
import com.nukkitx.protocol.bedrock.handler.BedrockPacketHandler;
import com.nukkitx.protocol.bedrock.packet.*;
import com.nukkitx.protocol.bedrock.util.EncryptionUtils;
import net.easecation.latencyproxy.LatencyProxy;
import io.netty.util.AsciiString;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import net.easecation.latencyproxy.Util;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Log4j2
@RequiredArgsConstructor
public class UpstreamPacketHandler implements BedrockPacketHandler {
    private final BedrockServerSession upstream;
    private final LatencyProxy proxy;
    private ProxySession proxySession;

    @Override
    public boolean handle(RequestNetworkSettingsPacket packet) {
        int protocolVersion = packet.getProtocolVersion();
        if (protocolVersion != LatencyProxy.PROTOCOL_VERSION) {
            PlayStatusPacket status = new PlayStatusPacket();
            if (protocolVersion > LatencyProxy.PROTOCOL_VERSION) {
                status.setStatus(PlayStatusPacket.Status.LOGIN_FAILED_SERVER_OLD);
            } else {
                status.setStatus(PlayStatusPacket.Status.LOGIN_FAILED_CLIENT_OLD);
            }
        }

        upstream.setPacketCodec(LatencyProxy.CODEC);
        upstream.setCompression(PacketCompressionAlgorithm.ZLIB);

        NetworkSettingsPacket networkSettingsPacket = new NetworkSettingsPacket();
        networkSettingsPacket.setCompressionThreshold(1);
        networkSettingsPacket.setCompressionAlgorithm(PacketCompressionAlgorithm.ZLIB);
        upstream.sendPacketImmediately(networkSettingsPacket);
        return true;
    }

    @Override
    public boolean handle(LoginPacket packet) {
        JsonNode certData;
        try {
            certData = Util.JSON_MAPPER.readTree(packet.getChainData().toByteArray());
        } catch (IOException e) {
            throw new RuntimeException("Certificate JSON can not be read.");
        }

        JsonNode certChainData = certData.get("chain");
        if (certChainData.getNodeType() != JsonNodeType.ARRAY) {
            throw new RuntimeException("Certificate data is not valid");
        }
        ArrayNode chainData = (ArrayNode) certChainData;

        boolean validChain;
        try {
            validChain = validateChainData(certChainData);

            log.debug("Is player data valid? {}", validChain);
            JWSObject jwt = JWSObject.parse(certChainData.get(certChainData.size() - 1).asText());
            JsonNode payload = Util.JSON_MAPPER.readTree(jwt.getPayload().toBytes());

            if (payload.get("extraData").getNodeType() != JsonNodeType.OBJECT) {
                throw new RuntimeException("AuthData was not found!");
            }

            JSONObject extraData = (JSONObject) jwt.getPayload().toJSONObject().get("extraData");

            if (payload.get("identityPublicKey").getNodeType() != JsonNodeType.STRING) {
                throw new RuntimeException("Identity Public Key was not found!");
            }
            ECPublicKey identityPublicKey = EncryptionUtils.generateKey(payload.get("identityPublicKey").textValue());

            JWSObject clientJwt = JWSObject.parse(packet.getSkinData().toString());
            verifyJwt(clientJwt, identityPublicKey);

            JSONObject skinData = new JSONObject(clientJwt.getPayload().toJSONObject());
            initializeProxySession(chainData, extraData, skinData);
        } catch (Exception e) {
            upstream.disconnect("disconnectionScreen.internalError.cantConnect");
            throw new RuntimeException("Unable to complete login", e);
        }
        return true;
    }

    private static boolean validateChainData(JsonNode data) throws Exception {
        ECPublicKey lastKey = null;
        boolean validChain = false;
        for (JsonNode node : data) {
            JWSObject jwt = JWSObject.parse(node.asText());

            if (!validChain) {
                validChain = verifyJwt(jwt, EncryptionUtils.getMojangPublicKey());
            }

            if (lastKey != null) {
                verifyJwt(jwt, lastKey);
            }

            JsonNode payloadNode = Util.JSON_MAPPER.readTree(jwt.getPayload().toString());
            JsonNode ipkNode = payloadNode.get("identityPublicKey");
            Preconditions.checkState(ipkNode != null && ipkNode.getNodeType() == JsonNodeType.STRING, "identityPublicKey node is missing in chain");
            lastKey = EncryptionUtils.generateKey(ipkNode.asText());
        }
        return validChain;
    }

    private static boolean verifyJwt(JWSObject jwt, ECPublicKey key) throws JOSEException {
        return jwt.verify(new DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader(), key));
    }

    private void initializeProxySession(ArrayNode chainData, JSONObject extraData, JSONObject skinData) {
        log.debug("Initializing proxy session");
        BedrockClient client = proxy.newClient();
        client.setRakNetVersion(LatencyProxy.CODEC.getRaknetProtocolVersion());
        client.connect(proxy.getTargetAddress()).whenComplete((downstream, throwable) -> {
            if (throwable != null) {
                log.error("Unable to connect to downstream server " + proxy.getTargetAddress(), throwable);
                return;
            }

            downstream.setPacketCodec(LatencyProxy.CODEC);
            ProxySession proxySession = new ProxySession(upstream, downstream);
            this.proxySession = proxySession;
            int shieldItemRuntimeId = proxy.getConfiguration().getShieldItemRuntimeId();
            downstream.getHardcodedBlockingId().set(shieldItemRuntimeId);

            SignedJWT authData = forgeAuthData(proxySession.getProxyKeyPair(), extraData);
            JWSObject skin = forgeSkinData(proxySession.getProxyKeyPair(), skinData);
            chainData.remove(chainData.size() - 1);
            chainData.add(authData.serialize());
            JsonNode json = Util.JSON_MAPPER.createObjectNode().set("chain", chainData);
            AsciiString chain;
            try {
                chain = new AsciiString(Util.JSON_MAPPER.writeValueAsBytes(json));
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }

            LoginPacket login = new LoginPacket();
            login.setChainData(chain);
            login.setSkinData(AsciiString.of(skin.serialize()));
            login.setProtocolVersion(LatencyProxy.PROTOCOL_VERSION);

            upstream.setBatchHandler(proxySession.createUpstreamBatchHandler());
            downstream.setBatchHandler(proxySession.createDownstreamTailHandler());
            downstream.setLogging(false);
            downstream.setPacketHandler(new DownstreamInitialPacketHandler(downstream, proxySession, login));
            downstream.addDisconnectHandler(disconnectReason -> {
                proxy.getClients().remove(client);
                upstream.disconnect();
            });
            upstream.getHardcodedBlockingId().set(shieldItemRuntimeId);

            RequestNetworkSettingsPacket packet = new RequestNetworkSettingsPacket();
            packet.setProtocolVersion(LatencyProxy.PROTOCOL_VERSION);
            downstream.sendPacketImmediately(packet);
        });
    }

    private static SignedJWT forgeAuthData(KeyPair pair, JSONObject extraData) {
        String publicKeyBase64 = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        URI x5u = URI.create(publicKeyBase64);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES384).x509CertURL(x5u).build();

        long timestamp = System.currentTimeMillis();
        Date nbf = new Date(timestamp - TimeUnit.SECONDS.toMillis(1));
        Date exp = new Date(timestamp + TimeUnit.DAYS.toMillis(1));

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .notBeforeTime(nbf)
                .expirationTime(exp)
                .issueTime(exp)
                .issuer("Mojang")
                .claim("certificateAuthority", true)
                .claim("extraData", extraData)
                .claim("identityPublicKey", publicKeyBase64)
                .build();

        SignedJWT jwt = new SignedJWT(header, claimsSet);

        try {
            EncryptionUtils.signJwt(jwt, (ECPrivateKey) pair.getPrivate());
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return jwt;
    }

    private static JWSObject forgeSkinData(KeyPair pair, JSONObject skinData) {
        URI x5u = URI.create(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES384).x509CertURL(x5u).build();

        JWSObject jws = new JWSObject(header, new Payload(skinData));

        try {
            EncryptionUtils.signJwt(jws, (ECPrivateKey) pair.getPrivate());
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return jws;
    }

    @Override
    public boolean handle(NetworkStackLatencyPacket packet) {
        if (!packet.isFromServer()) {
            NetworkStackLatencyPacket pong = new NetworkStackLatencyPacket();
            pong.setFromServer(false);
            pong.setTimestamp(packet.getTimestamp());
            upstream.sendPacket(pong);
            return true;
        }

        proxySession.pongC2P();
        return true;
    }

    @Override
    public boolean handle(SetLocalPlayerAsInitializedPacket packet) {
        proxySession.pingC2P();
        proxySession.pingP2S();
        return false;
    }
}
