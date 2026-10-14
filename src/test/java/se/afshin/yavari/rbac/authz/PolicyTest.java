package se.afshin.yavari.rbac.authz;

import org.junit.jupiter.api.Test;
import se.afshin.yavari.rbac.security.Caller;

import java.nio.charset.StandardCharsets;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static se.afshin.yavari.rbac.authz.Action.*;

class PolicyTest {

    private static Policy parse(String yaml) throws Exception {
        return Policy.parse(yaml.getBytes(StandardCharsets.UTF_8));
    }

    private static Caller user(String name, String... groups) {
        return new Caller(name, Set.of(groups), false);
    }

    private static Caller certificate(String principal) {
        return new Caller(principal, Set.of(), true);
    }

    private static final String POLICY = """
            rules:
              - groups: [orders-team]
                artifacts: [orders-value, orders-key]
                actions: [READ, WRITE]
              - principals: ["CN=payments-app", "User:CN=ci-pipeline, O=Acme"]
                groups: [payments-team]
                artifacts: payments-value
                actions: [READ, WRITE]
              - groups: [schema-admin]
                artifacts: ["*"]
                actions: [READ, WRITE, DELETE]
            """;

    @Test
    void groupGrantsListedArtifactsAndActions() throws Exception {
        Policy policy = parse(POLICY);
        assertThat(policy.allows(user("alice", "orders-team"), "orders-key", WRITE)).isTrue();
        assertThat(policy.allows(user("alice", "orders-team"), "orders-value", DELETE)).isFalse();
        assertThat(policy.allows(user("alice", "orders-team"), "payments-value", READ)).isFalse();
    }

    @Test
    void anyMatchingGroupIsEnough() throws Exception {
        assertThat(parse(POLICY).allows(user("bob", "other", "payments-team"), "payments-value", WRITE)).isTrue();
    }

    @Test
    void wildcardArtifactMatchesAny() throws Exception {
        assertThat(parse(POLICY).allows(user("root", "schema-admin"), "anything", DELETE)).isTrue();
    }

    @Test
    void principalGrantsCertificateCallers() throws Exception {
        Policy policy = parse(POLICY);
        assertThat(policy.allows(certificate("CN=payments-app"), "payments-value", WRITE)).isTrue();
        assertThat(policy.allows(certificate("CN=payments-app"), "orders-value", READ)).isFalse();
    }

    @Test
    void principalsAreNormalizedLikeTheCertificateSubject() throws Exception {
        // "User:" prefix dropped, "CN=a, O=b" written as RFC 2253 "CN=a,O=b"
        assertThat(parse(POLICY).allows(certificate("CN=ci-pipeline,O=Acme"), "payments-value", READ)).isTrue();
    }

    @Test
    void principalsNeverMatchOidcCallers() throws Exception {
        assertThat(parse(POLICY).allows(user("CN=payments-app"), "payments-value", READ)).isFalse();
    }

    @Test
    void emptyRulesAllowNothing() throws Exception {
        assertThat(parse("rules: []").allows(user("root", "schema-admin"), "orders", READ)).isFalse();
    }

    @Test
    void emptyFileIsRejected() {
        assertThatThrownBy(() -> parse("")).isInstanceOf(Exception.class);
    }

    @Test
    void unknownKeysAreRejected() {
        // The old format: roles + resources.
        assertThatThrownBy(() -> parse("""
                rules:
                  - roles: [orders-team]
                    resources: [{artifact: orders, actions: [READ]}]
                """)).isInstanceOf(Exception.class);
    }

    @Test
    void incompleteRulesAreRejected() {
        assertThatThrownBy(() -> parse("rules: [{artifacts: [a], actions: [READ]}]"))
                .hasMessageContaining("principals");
        assertThatThrownBy(() -> parse("rules: [{groups: [g], actions: [READ]}]"))
                .hasMessageContaining("artifacts");
        assertThatThrownBy(() -> parse("rules: [{groups: [g], artifacts: [a], actions: [UPDATE]}]"))
                .isInstanceOf(Exception.class);
    }
}
