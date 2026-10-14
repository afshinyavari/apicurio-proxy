package se.afshin.yavari.rbac.authz.kafka;

import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.common.acl.AccessControlEntry;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.acl.AclPermissionType;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class KafkaAclStoreTest {

    private static final AclBinding ORDERS_WRITE = new AclBinding(
            new ResourcePattern(ResourceType.TOPIC, "orders", PatternType.LITERAL),
            new AccessControlEntry("User:CN=orders-service", "*", AclOperation.WRITE, AclPermissionType.ALLOW));

    @Test
    void nothingIsLoadedUntilTheFirstSuccessfulRefresh() {
        KafkaAclStore store = new KafkaAclStore(() -> { throw new IllegalStateException("kafka down"); });
        assertThat(store.snapshot()).isEmpty();
        store.refresh();
        assertThat(store.snapshot()).isEmpty();
    }

    @Test
    void failedRefreshKeepsTheLastSnapshot() {
        AtomicReference<Collection<AclBinding>> next = new AtomicReference<>(List.of(ORDERS_WRITE));
        KafkaAclStore store = new KafkaAclStore(() -> {
            Collection<AclBinding> acls = next.get();
            if (acls == null) throw new IllegalStateException("kafka down");
            return acls;
        });
        store.refresh();
        next.set(null);
        store.refresh();
        assertThat(store.snapshot()).get().extracting(AclSnapshot::bindings).isEqualTo(List.of(ORDERS_WRITE));
    }

    @Test
    void disabledStoreHasAnEmptySnapshot() {
        KafkaAclStore store = new KafkaAclStore(Optional.empty(), "SSL", Optional.empty(), Optional.empty(), Optional.empty());
        assertThat(store.snapshot()).contains(AclSnapshot.EMPTY);
    }

    @Test
    void adminPropertiesReadThePemFiles(@TempDir Path dir) throws Exception {
        Path cert = Files.writeString(dir.resolve("tls.crt"), "CERT");
        Path key = Files.writeString(dir.resolve("tls.key"), "KEY");
        Path ca = Files.writeString(dir.resolve("ca.crt"), "CA");
        Properties p = KafkaAclStore.adminProperties("kafka:9093", "SSL",
                Optional.of(cert.toString()), Optional.of(key.toString()), Optional.of(ca.toString()));
        assertThat(p.get(CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG)).isEqualTo("kafka:9093");
        assertThat(p.get(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG)).isEqualTo("SSL");
        assertThat(p.get(SslConfigs.SSL_KEYSTORE_TYPE_CONFIG)).isEqualTo("PEM");
        assertThat(p.get(SslConfigs.SSL_KEYSTORE_CERTIFICATE_CHAIN_CONFIG)).isEqualTo("CERT");
        assertThat(p.get(SslConfigs.SSL_KEYSTORE_KEY_CONFIG)).isEqualTo("KEY");
        assertThat(p.get(SslConfigs.SSL_TRUSTSTORE_CERTIFICATES_CONFIG)).isEqualTo("CA");
    }

    @Test
    void adminPropertiesWithoutCertificatesHaveNoSslStores() {
        Properties p = KafkaAclStore.adminProperties("kafka:9092", "PLAINTEXT",
                Optional.empty(), Optional.empty(), Optional.empty());
        assertThat(p.get(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG)).isEqualTo("PLAINTEXT");
        assertThat(p).doesNotContainKeys(SslConfigs.SSL_KEYSTORE_TYPE_CONFIG, SslConfigs.SSL_TRUSTSTORE_TYPE_CONFIG);
    }
}
