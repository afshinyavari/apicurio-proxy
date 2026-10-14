package se.afshin.yavari.rbac.authz.kafka;

import org.apache.kafka.common.acl.AccessControlEntry;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.acl.AclPermissionType;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static se.afshin.yavari.rbac.authz.Action.*;
import static se.afshin.yavari.rbac.authz.kafka.AclSnapshot.topicOf;

class AclSnapshotTest {

    private static final String SVC = "CN=orders-service";

    private static AclBinding acl(String principal, ResourceType type, String name, PatternType pattern,
                                  AclOperation op, AclPermissionType perm) {
        return new AclBinding(new ResourcePattern(type, name, pattern),
                new AccessControlEntry("User:" + principal, "*", op, perm));
    }

    private static AclBinding allow(String name, PatternType pattern, AclOperation op) {
        return acl(SVC, ResourceType.TOPIC, name, pattern, op, AclPermissionType.ALLOW);
    }

    private static AclBinding deny(String principal, String name, PatternType pattern, AclOperation op) {
        return acl(principal, ResourceType.TOPIC, name, pattern, op, AclPermissionType.DENY);
    }

    private static AclSnapshot snapshot(AclBinding... bindings) {
        return new AclSnapshot(List.of(bindings));
    }

    // ── artifact → topic (TopicNameStrategy) ──────────────────────────────────

    @Test
    void stripsValueAndKeySuffixes() {
        assertThat(topicOf("orders-value")).isEqualTo("orders");
        assertThat(topicOf("orders-key")).isEqualTo("orders");
    }

    @Test
    void unknownSuffixMapsToSameName() {
        assertThat(topicOf("orders")).isEqualTo("orders");
        assertThat(topicOf("orders-schema")).isEqualTo("orders-schema");
        assertThat(topicOf("-value")).isEqualTo("-value");
    }

    @Test
    void wildcardArtifactMapsToWildcardTopic() {
        assertThat(topicOf("*")).isEqualTo("*");
        assertThat(topicOf(null)).isEqualTo("*");
    }

    // ── operation table ───────────────────────────────────────────────────────

    @Test
    void writeOnTopicGrantsReadAndWrite() {
        AclSnapshot acls = snapshot(allow("orders", PatternType.LITERAL, AclOperation.WRITE));
        assertThat(acls.allows(SVC, "orders-value", READ)).isTrue();
        assertThat(acls.allows(SVC, "orders-value", WRITE)).isTrue();
        assertThat(acls.allows(SVC, "orders-value", DELETE)).isFalse();
    }

    @Test
    void readOrDescribeOnTopicGrantsReadOnly() {
        assertThat(snapshot(allow("orders", PatternType.LITERAL, AclOperation.READ)).allows(SVC, "orders", READ)).isTrue();
        assertThat(snapshot(allow("orders", PatternType.LITERAL, AclOperation.DESCRIBE)).allows(SVC, "orders", READ)).isTrue();
        assertThat(snapshot(allow("orders", PatternType.LITERAL, AclOperation.READ)).allows(SVC, "orders", WRITE)).isFalse();
    }

    @Test
    void deleteAndAllMapAsExpected() {
        assertThat(snapshot(allow("orders", PatternType.LITERAL, AclOperation.DELETE)).allows(SVC, "orders", DELETE)).isTrue();
        assertThat(snapshot(allow("orders", PatternType.LITERAL, AclOperation.DELETE)).allows(SVC, "orders", READ)).isFalse();
        AclSnapshot all = snapshot(allow("orders", PatternType.LITERAL, AclOperation.ALL));
        assertThat(all.allows(SVC, "orders", READ)).isTrue();
        assertThat(all.allows(SVC, "orders", WRITE)).isTrue();
        assertThat(all.allows(SVC, "orders", DELETE)).isTrue();
    }

    // ── pattern matching ──────────────────────────────────────────────────────

    @Test
    void prefixedPatternMatchesTopicsWithThatPrefix() {
        AclSnapshot acls = snapshot(allow("orders", PatternType.PREFIXED, AclOperation.WRITE));
        assertThat(acls.allows(SVC, "orders.created-value", WRITE)).isTrue();
        assertThat(acls.allows(SVC, "payments-value", WRITE)).isFalse();
    }

    @Test
    void literalWildcardNameMatchesEveryTopicIncludingStar() {
        AclSnapshot acls = snapshot(allow("*", PatternType.LITERAL, AclOperation.ALL));
        assertThat(acls.allows(SVC, "anything", DELETE)).isTrue();
        assertThat(acls.allows(SVC, "*", READ)).isTrue();
    }

    @Test
    void starArtifactRequiresWildcardAcl() {
        assertThat(snapshot(allow("orders", PatternType.PREFIXED, AclOperation.ALL)).allows(SVC, "*", READ)).isFalse();
    }

    @Test
    void wildcardPrincipalApplies() {
        AclSnapshot acls = snapshot(acl("*", ResourceType.TOPIC, "orders", PatternType.LITERAL,
                AclOperation.READ, AclPermissionType.ALLOW));
        assertThat(acls.allows("CN=someone-else", "orders", READ)).isTrue();
    }

    @Test
    void otherPrincipalsAndResourceTypesAreIgnored() {
        AclSnapshot acls = snapshot(
                acl("CN=other", ResourceType.TOPIC, "orders", PatternType.LITERAL, AclOperation.ALL, AclPermissionType.ALLOW),
                acl(SVC, ResourceType.GROUP, "orders", PatternType.LITERAL, AclOperation.ALL, AclPermissionType.ALLOW));
        assertThat(acls.allows(SVC, "orders", READ)).isFalse();
    }

    // ── deny precedence ───────────────────────────────────────────────────────

    @Test
    void denyOnOperationBeatsAllow() {
        AclSnapshot acls = snapshot(
                allow("*", PatternType.LITERAL, AclOperation.ALL),
                deny(SVC, "orders", PatternType.LITERAL, AclOperation.WRITE));
        assertThat(acls.allows(SVC, "orders", WRITE)).isFalse();
        // READ is still granted through ALL (the DENY targets WRITE only)
        assertThat(acls.allows(SVC, "orders", READ)).isTrue();
        assertThat(acls.allows(SVC, "payments", WRITE)).isTrue();
    }

    @Test
    void denyAllBeatsEverything() {
        AclSnapshot acls = snapshot(
                allow("orders", PatternType.LITERAL, AclOperation.WRITE),
                deny(SVC, "orders", PatternType.PREFIXED, AclOperation.ALL));
        assertThat(acls.allows(SVC, "orders", READ)).isFalse();
        assertThat(acls.allows(SVC, "orders", WRITE)).isFalse();
    }

    @Test
    void principalsAreCountedOnce() {
        AclSnapshot acls = snapshot(
                allow("orders", PatternType.LITERAL, AclOperation.WRITE),
                allow("payments", PatternType.LITERAL, AclOperation.READ),
                deny("CN=other", "orders", PatternType.LITERAL, AclOperation.ALL),
                acl("*", ResourceType.TOPIC, "shared", PatternType.LITERAL, AclOperation.READ, AclPermissionType.ALLOW));
        assertThat(acls.principalCount()).isEqualTo(3);
        assertThat(AclSnapshot.EMPTY.principalCount()).isZero();
    }

    @Test
    void emptySnapshotAllowsNothing() {
        assertThat(AclSnapshot.EMPTY.allows(SVC, "orders", READ)).isFalse();
    }

    // ── explicit DENY lookup (veto for policy-file grants) ───────────────────

    @Test
    void denyOnSameOperationOrAllIsFound() {
        assertThat(snapshot(deny(SVC, "orders", PatternType.LITERAL, AclOperation.WRITE)).denies(SVC, "orders-value", WRITE)).isTrue();
        assertThat(snapshot(deny(SVC, "ord", PatternType.PREFIXED, AclOperation.ALL)).denies(SVC, "orders", READ)).isTrue();
        assertThat(snapshot(deny("*", "orders", PatternType.LITERAL, AclOperation.DELETE)).denies(SVC, "orders", DELETE)).isTrue();
    }

    @Test
    void denyOnOtherOperationTopicOrPrincipalIsNotFound() {
        assertThat(snapshot(deny(SVC, "orders", PatternType.LITERAL, AclOperation.WRITE)).denies(SVC, "orders", READ)).isFalse();
        assertThat(snapshot(deny(SVC, "orders", PatternType.LITERAL, AclOperation.DESCRIBE)).denies(SVC, "orders", READ)).isFalse();
        assertThat(snapshot(deny(SVC, "payments", PatternType.LITERAL, AclOperation.ALL)).denies(SVC, "orders", READ)).isFalse();
        assertThat(snapshot(deny("CN=other", "orders", PatternType.LITERAL, AclOperation.ALL)).denies(SVC, "orders", READ)).isFalse();
    }

    @Test
    void allowEntriesAreNotDenies() {
        assertThat(snapshot(allow("orders", PatternType.LITERAL, AclOperation.ALL)).denies(SVC, "orders", WRITE)).isFalse();
    }
}
