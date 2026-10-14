package se.afshin.yavari.rbac.authz.kafka;

import io.quarkus.logging.Log;
import io.quarkus.scheduler.Scheduled;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclBindingFilter;
import org.apache.kafka.common.config.SslConfigs;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Keeps a snapshot of every ACL binding in the Kafka cluster, refreshed every
 * {@code proxy.kafka.acl-refresh-interval}. A failed refresh keeps the last snapshot.
 *
 * <p>Enabled by {@code proxy.kafka.bootstrap}. The admin client connects with
 * {@code proxy.kafka.security-protocol} (default SSL) and PEM files: {@code proxy.kafka.ssl.cert}
 * and {@code proxy.kafka.ssl.key} (PKCS#8) for its own certificate, {@code proxy.kafka.ssl.ca}
 * for the brokers' CA. Without a bootstrap address the snapshot is empty and certificate callers
 * get only what the policy file grants their principal.
 */
@ApplicationScoped
public class KafkaAclStore {

    private final Supplier<Collection<AclBinding>> loader;
    private final Admin admin;
    private volatile AclSnapshot snapshot;

    @Inject
    KafkaAclStore(@ConfigProperty(name = "proxy.kafka.bootstrap") Optional<String> bootstrap,
                  @ConfigProperty(name = "proxy.kafka.security-protocol", defaultValue = "SSL") String securityProtocol,
                  @ConfigProperty(name = "proxy.kafka.ssl.cert") Optional<String> cert,
                  @ConfigProperty(name = "proxy.kafka.ssl.key") Optional<String> key,
                  @ConfigProperty(name = "proxy.kafka.ssl.ca") Optional<String> ca) {
        if (bootstrap.isEmpty()) {
            Log.info("proxy.kafka.bootstrap unset: certificate callers are authorized by the policy file only");
            this.admin = null;
            this.loader = null;
            this.snapshot = AclSnapshot.EMPTY;
            return;
        }
        this.admin = Admin.create(adminProperties(bootstrap.get(), securityProtocol, cert, key, ca));
        this.loader = () -> {
            try {
                return admin.describeAcls(AclBindingFilter.ANY).values().get();
            } catch (Exception e) {
                throw new IllegalStateException("describeAcls failed: " + e.getMessage(), e);
            }
        };
    }

    /** Test seam: an explicit loader; nothing is loaded until {@link #refresh()}. */
    KafkaAclStore(Supplier<Collection<AclBinding>> loader) {
        this.admin = null;
        this.loader = loader;
    }

    /** The current snapshot; empty while the ACLs are enabled but have never been loaded. */
    public Optional<AclSnapshot> snapshot() {
        return Optional.ofNullable(snapshot);
    }

    public void update(Collection<AclBinding> bindings) {
        snapshot = new AclSnapshot(List.copyOf(bindings));
    }

    @Scheduled(every = "${proxy.kafka.acl-refresh-interval}", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void refresh() {
        if (loader == null) return;
        try {
            AclSnapshot previous = snapshot;
            update(loader.get());
            AclSnapshot current = snapshot;
            // Logged on the first load and whenever the ACLs change, not on every refresh.
            if (previous == null || !Set.copyOf(previous.bindings()).equals(Set.copyOf(current.bindings()))) {
                Log.infof("Loaded %d ACL bindings for %d principals",
                        current.bindings().size(), current.principalCount());
            }
        } catch (Exception e) {
            AclSnapshot kept = snapshot;
            Log.errorf("ACL refresh failed, keeping %s: %s",
                    kept == null ? "nothing" : kept.bindings().size() + " bindings", e.getMessage());
        }
    }

    @PreDestroy
    void close() {
        if (admin != null) admin.close();
    }

    static Properties adminProperties(String bootstrap, String securityProtocol,
                                      Optional<String> cert, Optional<String> key, Optional<String> ca) {
        Properties p = new Properties();
        p.put(CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG, bootstrap);
        p.put(CommonClientConfigs.CLIENT_ID_CONFIG, "apicurio-rbac-proxy-acl");
        p.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, securityProtocol);
        p.put(CommonClientConfigs.REQUEST_TIMEOUT_MS_CONFIG, 15_000);
        p.put(CommonClientConfigs.DEFAULT_API_TIMEOUT_MS_CONFIG, 20_000);
        if (cert.isPresent() && key.isPresent()) {
            p.put(SslConfigs.SSL_KEYSTORE_TYPE_CONFIG, "PEM");
            p.put(SslConfigs.SSL_KEYSTORE_CERTIFICATE_CHAIN_CONFIG, read(cert.get()));
            p.put(SslConfigs.SSL_KEYSTORE_KEY_CONFIG, read(key.get()));
        }
        if (ca.isPresent()) {
            p.put(SslConfigs.SSL_TRUSTSTORE_TYPE_CONFIG, "PEM");
            p.put(SslConfigs.SSL_TRUSTSTORE_CERTIFICATES_CONFIG, read(ca.get()));
        }
        return p;
    }

    private static String read(String path) {
        try {
            return Files.readString(Path.of(path));
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read " + path, e);
        }
    }
}
