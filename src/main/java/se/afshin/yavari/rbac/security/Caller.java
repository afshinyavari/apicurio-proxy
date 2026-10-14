package se.afshin.yavari.rbac.security;

import io.quarkus.security.identity.SecurityIdentity;

import java.util.Set;

/**
 * Who is calling, as authorization sees it: a principal name and the caller's groups.
 *
 * <p>An OIDC caller is named by its token and carries the groups from the token's group claim.
 * A certificate caller is named by its Kafka principal (see {@link CertificatePrincipalAugmentor})
 * and carries no groups; {@code certificate} tells authorization to consult the Kafka ACLs.
 */
public record Caller(String name, Set<String> groups, boolean certificate) {

    /** Identity attribute that marks a caller authenticated by a client certificate. */
    public static final String CERTIFICATE_ATTRIBUTE = "proxy.certificate-principal";

    public Caller {
        groups = Set.copyOf(groups);
    }

    public static Caller of(SecurityIdentity identity) {
        boolean certificate = identity.getAttribute(CERTIFICATE_ATTRIBUTE) != null;
        return new Caller(identity.getPrincipal().getName(),
                certificate ? Set.of() : identity.getRoles(), certificate);
    }
}
