package se.afshin.yavari.rbac.authz.kafka;

import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.acl.AclPermissionType;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import se.afshin.yavari.rbac.authz.Action;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * A set of Kafka ACL bindings, asked about artifacts. Artifacts follow TopicNameStrategy:
 * {@code orders-value} and {@code orders-key} belong to topic {@code orders}. The principal's
 * topic permissions decide the artifact actions: READ/DESCRIBE → READ, WRITE → READ+WRITE,
 * DELETE → DELETE, ALL → everything.
 *
 * <p>Evaluation follows Kafka's authorizer: a matching DENY for an operation (or ALL) wins over
 * any ALLOW; LITERAL patterns match exactly (or via the {@code *} name), PREFIXED patterns match
 * by prefix; principal {@code User:*} matches everyone. Host is ignored.
 */
public record AclSnapshot(List<AclBinding> bindings) {

    public static final AclSnapshot EMPTY = new AclSnapshot(List.of());

    private static final String WILDCARD = "*";
    private static final List<String> SUBJECT_SUFFIXES = List.of("-value", "-key");

    public AclSnapshot {
        bindings = List.copyOf(bindings);
    }

    /** Distinct principals the bindings name, {@code User:*} included. */
    public long principalCount() {
        return bindings.stream().map(b -> b.entry().principal()).distinct().count();
    }

    /** Some topic operation granting {@code action} is allowed and not denied. */
    public boolean allows(String principal, String artifact, Action action) {
        String topic = topicOf(artifact);
        for (AclOperation op : grantingOperations(action)) {
            if (has(AclPermissionType.ALLOW, principal, topic, op)
                    && !has(AclPermissionType.DENY, principal, topic, op)) {
                return true;
            }
        }
        return false;
    }

    /** A DENY on the operation named like {@code action} (or ALL). A DENY on DESCRIBE does not
     *  veto READ, as in Kafka. */
    public boolean denies(String principal, String artifact, Action action) {
        return has(AclPermissionType.DENY, principal, topicOf(artifact), AclOperation.valueOf(action.name()));
    }

    /** The topic an artifact belongs to under TopicNameStrategy. */
    static String topicOf(String artifact) {
        if (artifact == null || WILDCARD.equals(artifact)) return WILDCARD;
        for (String suffix : SUBJECT_SUFFIXES) {
            if (artifact.length() > suffix.length() && artifact.endsWith(suffix)) {
                return artifact.substring(0, artifact.length() - suffix.length());
            }
        }
        return artifact;
    }

    /** ALL is not listed: an entry with operation ALL matches every operation in {@link #has},
     *  so a specific DENY (e.g. on WRITE) still wins over an ALLOW ALL, as in Kafka. */
    private static Set<AclOperation> grantingOperations(Action action) {
        return switch (action) {
            case READ -> EnumSet.of(AclOperation.READ, AclOperation.DESCRIBE, AclOperation.WRITE);
            case WRITE -> EnumSet.of(AclOperation.WRITE);
            case DELETE -> EnumSet.of(AclOperation.DELETE);
        };
    }

    private boolean has(AclPermissionType permission, String principal, String topic, AclOperation op) {
        String kafkaPrincipal = "User:" + principal;
        return bindings.stream().anyMatch(b ->
                b.entry().permissionType() == permission
                        && (b.entry().operation() == op || b.entry().operation() == AclOperation.ALL)
                        && (b.entry().principal().equals(kafkaPrincipal) || b.entry().principal().equals("User:*"))
                        && matchesTopic(b.pattern(), topic));
    }

    private static boolean matchesTopic(ResourcePattern pattern, String topic) {
        if (pattern.resourceType() != ResourceType.TOPIC) return false;
        if (pattern.patternType() == PatternType.LITERAL) {
            return WILDCARD.equals(pattern.name()) || pattern.name().equals(topic);
        }
        if (pattern.patternType() == PatternType.PREFIXED) {
            return !WILDCARD.equals(topic) && topic.startsWith(pattern.name());
        }
        return false;
    }
}
