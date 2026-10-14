package se.afshin.yavari.rbac.authz;

import org.apache.kafka.common.acl.AccessControlEntry;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.acl.AclPermissionType;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.afshin.yavari.rbac.authz.kafka.AclSnapshot;
import se.afshin.yavari.rbac.security.Caller;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static se.afshin.yavari.rbac.authz.Action.*;

/** OIDC callers → policy groups; certificate callers → Kafka ACLs, plus policy principals with a
 *  Kafka DENY as veto. */
class AuthorizerTest {

    private static Policy policy;

    @BeforeAll
    static void loadPolicy() throws Exception {
        policy = Policy.parse("""
                rules:
                  - groups: [orders-team]
                    artifacts: [orders-value]
                    actions: [READ, WRITE]
                  - principals: ["CN=payments-app"]
                    artifacts: [payments-value]
                    actions: [READ, WRITE]
                """.getBytes(StandardCharsets.UTF_8));
    }

    private static AclBinding topicAcl(String principal, String topic, AclOperation op, AclPermissionType perm) {
        return new AclBinding(new ResourcePattern(ResourceType.TOPIC, topic, PatternType.LITERAL),
                new AccessControlEntry("User:" + principal, "*", op, perm));
    }

    private static final AclSnapshot ORDERS_WRITE = new AclSnapshot(List.of(
            topicAcl("CN=orders-service", "orders", AclOperation.WRITE, AclPermissionType.ALLOW)));

    private static Caller oidc(String name, String... groups) {
        return new Caller(name, Set.of(groups), false);
    }

    private static Caller certificate(String principal) {
        return new Caller(principal, Set.of(), true);
    }

    private static boolean allowed(AclSnapshot acls, Caller caller, String artifact, Action action) {
        return Authorizer.isAllowed(policy, acls, caller, artifact, action);
    }

    @Test
    void oidcCallerUsesPolicyGroups() {
        assertThat(allowed(ORDERS_WRITE, oidc("alice", "orders-team"), "orders-value", WRITE)).isTrue();
        assertThat(allowed(ORDERS_WRITE, oidc("alice", "orders-team"), "payments-value", READ)).isFalse();
    }

    @Test
    void oidcCallerNeverConsultsAcls() {
        assertThat(allowed(ORDERS_WRITE, oidc("CN=orders-service"), "orders-value", WRITE)).isFalse();
    }

    @Test
    void certificateCallerUsesKafkaAcls() {
        assertThat(allowed(ORDERS_WRITE, certificate("CN=orders-service"), "orders-value", WRITE)).isTrue();
        assertThat(allowed(ORDERS_WRITE, certificate("CN=orders-service"), "orders-key", READ)).isTrue();
        assertThat(allowed(ORDERS_WRITE, certificate("CN=orders-service"), "payments-value", READ)).isFalse();
    }

    @Test
    void certificateCallerGetsPolicyRulesForItsPrincipal() {
        assertThat(allowed(AclSnapshot.EMPTY, certificate("CN=payments-app"), "payments-value", WRITE)).isTrue();
        assertThat(allowed(AclSnapshot.EMPTY, certificate("CN=payments-app"), "payments-value", DELETE)).isFalse();
    }

    @Test
    void kafkaDenyVetoesPolicyGrant() {
        AclSnapshot deny = new AclSnapshot(List.of(
                topicAcl("CN=payments-app", "payments", AclOperation.WRITE, AclPermissionType.DENY)));
        assertThat(allowed(deny, certificate("CN=payments-app"), "payments-value", WRITE)).isFalse();
        // the DENY targets WRITE only
        assertThat(allowed(deny, certificate("CN=payments-app"), "payments-value", READ)).isTrue();
    }

    @Test
    void certificateCallerIsDeniedWhileAclsAreNotLoaded() {
        // Enabled but never loaded: a Kafka DENY cannot be ruled out, so fail closed.
        assertThat(allowed(null, certificate("CN=payments-app"), "payments-value", WRITE)).isFalse();
        assertThat(allowed(null, oidc("alice", "orders-team"), "orders-value", WRITE)).isTrue();
    }
}
