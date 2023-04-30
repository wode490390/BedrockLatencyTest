package net.easecation.latencyproxy;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.ToString;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;

@Getter
@ToString
public class Configuration {
    private Address proxy;
    private Address destination;

    @JsonProperty("shield-item-runtime-id")
    private int shieldItemRuntimeId;

    public static Configuration load(Path path) throws IOException {
        try (BufferedReader reader = Files.newBufferedReader(path)) {
            return Util.YAML_MAPPER.readValue(reader, Configuration.class);
        }
    }

    @Getter
    @ToString
    public static class Address {
        private String host;
        private int port;

        InetSocketAddress getAddress() {
            return new InetSocketAddress(host, port);
        }
    }
}
