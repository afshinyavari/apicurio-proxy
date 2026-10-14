package se.afshin.yavari.rbac.authz;

import io.quarkus.logging.Log;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Holds the current {@link Policy}. The file is loaded at startup (a broken file fails startup)
 * and then polled every {@code proxy.policy.reload-interval}; changed content is swapped in
 * without a restart, and a broken change keeps the policy already loaded.
 *
 * <p>Polling by content, rather than watching the file name, is what makes a Kubernetes
 * ConfigMap update visible: kubelet never writes to the mounted file, it swaps the
 * {@code ..data} symlink the file resolves through.
 */
@ApplicationScoped
public class PolicyStore {

    private final Path file;
    private volatile Policy policy;
    private byte[] lastSeen;
    private boolean unreadable;

    @Inject
    public PolicyStore(@ConfigProperty(name = "proxy.policy.file") String file) {
        this.file = Path.of(file);
    }

    void onStart(@Observes StartupEvent event) throws IOException {
        loadInitial();
    }

    @Scheduled(every = "${proxy.policy.reload-interval}", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void poll() {
        reloadIfChanged();
    }

    public Policy current() {
        Policy p = policy;
        return p == null ? Policy.EMPTY : p;
    }

    public boolean isLoaded() {
        return policy != null;
    }

    synchronized void loadInitial() throws IOException {
        byte[] content = Files.readAllBytes(file);
        swapIn(content);
    }

    /** One poll; {@code true} when changed content was loaded. */
    synchronized boolean reloadIfChanged() {
        byte[] content;
        try {
            content = Files.readAllBytes(file);
        } catch (IOException e) {
            if (!unreadable) Log.errorf("Cannot read %s, keeping current policy: %s", file, e);
            unreadable = true;
            return false;
        }
        unreadable = false;
        if (Arrays.equals(content, lastSeen)) return false;
        try {
            swapIn(content);
            return true;
        } catch (Exception e) {
            // Not offered again until the file changes.
            lastSeen = content;
            Log.errorf("Reload of %s failed, keeping current policy: %s", file, e.getMessage());
            return false;
        }
    }

    private void swapIn(byte[] content) throws IOException {
        Policy parsed = Policy.parse(content);
        policy = parsed;
        lastSeen = content;
        Log.infof("Loaded %d policy rules from %s", parsed.rules().size(), file);
    }
}
