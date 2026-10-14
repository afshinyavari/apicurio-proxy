package se.afshin.yavari.rbac.authz;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyStoreTest {

    private static final String ONE_RULE = "rules: [{groups: [a], artifacts: [x], actions: [READ]}]";
    private static final String TWO_RULES = "rules: [{groups: [a], artifacts: [x], actions: [READ]},"
            + " {groups: [b], artifacts: [y], actions: [READ]}]";

    @TempDir
    Path dir;

    /**
     * Lays the volume out the way kubelet does for a ConfigMap: the visible file is a symlink
     * through {@code ..data}, which points at a timestamped directory. Returns the visible file.
     */
    private Path configMapVolume(String content) throws Exception {
        publish("..rev1", content);
        Files.createSymbolicLink(dir.resolve("..data"), Path.of("..rev1"));
        return Files.createSymbolicLink(dir.resolve("policy.yaml"), Path.of("..data", "policy.yaml"));
    }

    private void publish(String revision, String content) throws Exception {
        Path revisionDir = Files.createDirectory(dir.resolve(revision));
        Files.writeString(revisionDir.resolve("policy.yaml"), content);
    }

    /** A ConfigMap update: new timestamped directory, then {@code ..data} is swapped atomically.
     *  The visible {@code policy.yaml} symlink itself is never touched. */
    private void updateConfigMap(String revision, String content) throws Exception {
        publish(revision, content);
        Path tmp = Files.createSymbolicLink(dir.resolve("..data_tmp"), Path.of(revision));
        Files.move(tmp, dir.resolve("..data"), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    private static PolicyStore store(Path file) {
        return new PolicyStore(file.toString());
    }

    @Test
    void configMapUpdateIsLoadedWithoutRestart() throws Exception {
        PolicyStore store = store(configMapVolume(ONE_RULE));
        store.loadInitial();
        assertThat(store.current().rules()).hasSize(1);

        updateConfigMap("..rev2", TWO_RULES);

        assertThat(store.reloadIfChanged()).isTrue();
        assertThat(store.current().rules()).hasSize(2);
    }

    @Test
    void unchangedContentIsNotLoadedAgain() throws Exception {
        PolicyStore store = store(Files.writeString(dir.resolve("policy.yaml"), ONE_RULE));
        store.loadInitial();
        assertThat(store.reloadIfChanged()).isFalse();
    }

    @Test
    void brokenFileAtStartupFails() throws Exception {
        PolicyStore store = store(Files.writeString(dir.resolve("policy.yaml"), "rules: [{nonsense: 1}]"));
        assertThatThrownBy(store::loadInitial).isInstanceOf(Exception.class);
        assertThat(store.isLoaded()).isFalse();
    }

    @Test
    void missingFileAtStartupFails() {
        assertThatThrownBy(() -> store(dir.resolve("absent.yaml")).loadInitial()).isInstanceOf(Exception.class);
    }

    @Test
    void brokenChangeKeepsTheCurrentPolicyUntilTheFileChangesAgain() throws Exception {
        Path file = Files.writeString(dir.resolve("policy.yaml"), ONE_RULE);
        PolicyStore store = store(file);
        store.loadInitial();

        Files.writeString(file, "rules: [{nonsense: 1}]");
        assertThat(store.reloadIfChanged()).isFalse();
        assertThat(store.current().rules()).hasSize(1);

        Files.writeString(file, TWO_RULES);
        assertThat(store.reloadIfChanged()).isTrue();
        assertThat(store.current().rules()).hasSize(2);
    }

    @Test
    void unreadableFileIsSkippedAndPickedUpWhenItReturns() throws Exception {
        Path file = Files.writeString(dir.resolve("policy.yaml"), ONE_RULE);
        PolicyStore store = store(file);
        store.loadInitial();

        Files.delete(file);
        assertThat(store.reloadIfChanged()).isFalse();
        assertThat(store.current().rules()).hasSize(1);

        Files.writeString(file, TWO_RULES);
        assertThat(store.reloadIfChanged()).isTrue();
        assertThat(store.current().rules()).hasSize(2);
    }
}
