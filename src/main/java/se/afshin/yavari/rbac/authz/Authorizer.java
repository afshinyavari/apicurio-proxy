package se.afshin.yavari.rbac.authz;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import se.afshin.yavari.rbac.authz.kafka.AclSnapshot;
import se.afshin.yavari.rbac.authz.kafka.KafkaAclStore;
import se.afshin.yavari.rbac.security.Caller;

import java.util.List;
import java.util.Optional;

/**
 * Decides whether a caller may perform an action on an artifact.
 *
 * <p>An OIDC caller is judged by the policy file through its groups. A certificate caller is
 * allowed by its Kafka ACLs, or by policy rules naming its principal; a Kafka DENY on the action
 * vetoes such a policy grant. While the Kafka ACLs are enabled but not yet loaded, a certificate
 * caller is denied outright, since a DENY cannot be ruled out.
 */
@ApplicationScoped
public class Authorizer {

    @Inject PolicyStore policies;
    @Inject KafkaAclStore acls;

    /** The first of {@code artifacts} the caller may perform {@code action} on. */
    public Optional<String> firstAllowed(Caller caller, List<String> artifacts, Action action) {
        Policy policy = policies.current();
        AclSnapshot snapshot = acls.snapshot().orElse(null);
        return artifacts.stream().filter(a -> isAllowed(policy, snapshot, caller, a, action)).findFirst();
    }

    /** @param acls {@code null} when the ACLs are enabled but not loaded */
    static boolean isAllowed(Policy policy, AclSnapshot acls, Caller caller, String artifact, Action action) {
        if (caller.certificate()) {
            if (acls == null) return false;
            if (acls.allows(caller.name(), artifact, action)) return true;
            if (acls.denies(caller.name(), artifact, action)) return false;
        }
        return policy.allows(caller, artifact, action);
    }
}
