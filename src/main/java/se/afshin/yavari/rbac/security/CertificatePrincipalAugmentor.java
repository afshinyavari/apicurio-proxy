package se.afshin.yavari.rbac.security;

import io.quarkus.logging.Log;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.credential.CertificateCredential;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.apache.kafka.common.security.ssl.SslPrincipalMapper;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.io.IOException;
import java.util.Optional;

/**
 * Names a client-certificate identity by its Kafka principal, so the proxy and the brokers see
 * the same caller. The subject DN goes through the brokers' own {@code ssl.principal.mapping.rules}
 * ({@code proxy.mtls.principal-mapping-rules}, default {@code DEFAULT} = the full RFC 2253 DN),
 * evaluated by Kafka's mapper. A certificate no rule matches is rejected, as Kafka does.
 */
@ApplicationScoped
public class CertificatePrincipalAugmentor implements SecurityIdentityAugmentor {

    private final SslPrincipalMapper mapper;

    @Inject
    public CertificatePrincipalAugmentor(
            @ConfigProperty(name = "proxy.mtls.principal-mapping-rules", defaultValue = "DEFAULT") String rules) {
        this.mapper = SslPrincipalMapper.fromRules(rules);
        Log.infof("Certificate principals mapped by rules %s", rules);
    }

    @Override
    public Uni<SecurityIdentity> augment(SecurityIdentity identity, AuthenticationRequestContext context) {
        CertificateCredential credential = identity.getCredential(CertificateCredential.class);
        if (credential == null || credential.getCertificate() == null) {
            return Uni.createFrom().item(identity);
        }
        String subject = credential.getCertificate().getSubjectX500Principal().getName();
        Optional<String> principal = principalFor(subject);
        if (principal.isEmpty()) {
            return Uni.createFrom().failure(
                    new AuthenticationFailedException("No principal mapping rule matches " + subject));
        }
        return Uni.createFrom().item(QuarkusSecurityIdentity.builder(identity)
                .setPrincipal(new QuarkusPrincipal(principal.get()))
                .addAttribute(Caller.CERTIFICATE_ATTRIBUTE, Boolean.TRUE)
                .build());
    }

    /** The Kafka principal for an RFC 2253 subject; empty when no rule matches. */
    Optional<String> principalFor(String subject) {
        try {
            return Optional.of(mapper.getName(subject));
        } catch (IOException noMatchingRule) {
            return Optional.empty();
        }
    }
}
