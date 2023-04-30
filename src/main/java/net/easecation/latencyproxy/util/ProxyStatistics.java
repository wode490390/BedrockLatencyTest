package net.easecation.latencyproxy.util;

import net.easecation.latencyproxy.network.ProxySession;
import lombok.extern.log4j.Log4j2;

import javax.management.*;
import java.lang.management.ManagementFactory;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Log4j2
public final class ProxyStatistics implements DynamicMBean {
    private final MBeanInfo mBeanInfo;
    private final Map<String, AttributeDescription> attributeDescriptionByName;

    private ProxyStatistics() {
        attributeDescriptionByName = Stream.of(
                new AttributeDescription("latencyC2P", () -> ProxySession.latencyC2P / 1_000_000f, "C2P latency (ms)", Float.TYPE),
                new AttributeDescription("latencyP2S", () -> ProxySession.latencyP2S / 1_000_000f, "P2S latency (ms)", Float.TYPE)
        ).collect(Collectors.toMap(description -> description.name, Function.identity()));

        mBeanInfo = new MBeanInfo("ProxyStatistics", "metrics for proxy server", attributeDescriptionByName.values().stream()
                .map(AttributeDescription::asMBeanAttributeInfo)
                .toArray(MBeanAttributeInfo[]::new), null, null, new MBeanNotificationInfo[0]);
    }

    public static void registerJmxMonitoring() {
        try {
            ManagementFactory.getPlatformMBeanServer().registerMBean(new ProxyStatistics(), new ObjectName("net.easecation.latencyproxy:type=Proxy"));
        } catch (InstanceAlreadyExistsException | MBeanRegistrationException | NotCompliantMBeanException | MalformedObjectNameException e) {
            log.error("Failed to initialise server as JMX bean", e);
        }
    }

    @Override
    public Object getAttribute(String attribute) {
        AttributeDescription description = attributeDescriptionByName.get(attribute);
        return description == null ? null : description.getter.get();
    }

    @Override
    public void setAttribute(Attribute attribute) {
    }

    @Override
    public AttributeList getAttributes(String[] attributes) {
        return new AttributeList(Arrays.stream(attributes)
                .map(attributeDescriptionByName::get)
                .filter(Objects::nonNull)
                .map(description -> new Attribute(description.name, description.getter.get()))
                .collect(Collectors.toList()));
    }

    @Override
    public AttributeList setAttributes(AttributeList attributes) {
        return new AttributeList();
    }

    @Override
    public Object invoke(String actionName, Object[] params, String[] signature) {
        return null;
    }

    @Override
    public MBeanInfo getMBeanInfo() {
        return mBeanInfo;
    }

    private static final class AttributeDescription {
        private final String name;
        private final Supplier<Object> getter;
        private final String description;
        private final Class<?> type;

        private AttributeDescription(String name, Supplier<Object> getter, String description, Class<?> type) {
            this.name = name;
            this.getter = getter;
            this.description = description;
            this.type = type;
        }

        private MBeanAttributeInfo asMBeanAttributeInfo() {
            return new MBeanAttributeInfo(name, type.getSimpleName(), description, true, false, false);
        }
    }
}
