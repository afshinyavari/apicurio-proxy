package se.afshin.yavari.rbac.authz;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Readiness;
import se.afshin.yavari.rbac.authz.kafka.KafkaAclStore;

/** Ready once the policy file is loaded and, when enabled, the first ACL snapshot is fetched. */
@Readiness
@ApplicationScoped
public class AuthorizationReadiness implements HealthCheck {

    @Inject PolicyStore policies;
    @Inject KafkaAclStore acls;

    @Override
    public HealthCheckResponse call() {
        boolean up = policies.isLoaded() && acls.snapshot().isPresent();
        return HealthCheckResponse.named("authorization").status(up).build();
    }
}
