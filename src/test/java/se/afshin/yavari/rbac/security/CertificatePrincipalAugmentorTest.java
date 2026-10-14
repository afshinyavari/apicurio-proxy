package se.afshin.yavari.rbac.security;

import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificatePrincipalAugmentorTest {

    private static CertificatePrincipalAugmentor rules(String rules) {
        return new CertificatePrincipalAugmentor(rules);
    }

    @Test
    void defaultRuleKeepsTheRfc2253Subject() {
        assertThat(rules("DEFAULT").principalFor("CN=orders-service,O=Acme")).contains("CN=orders-service,O=Acme");
    }

    @Test
    void rulesRewriteTheSubjectLikeTheBroker() {
        CertificatePrincipalAugmentor cnOnly = rules("RULE:^CN=([^,]+),.*$/$1/L,DEFAULT");
        assertThat(cnOnly.principalFor("CN=Orders-Service,O=Acme")).contains("orders-service");
        assertThat(cnOnly.principalFor("CN=bare")).contains("CN=bare");
    }

    @Test
    void subjectNoRuleMatchesHasNoPrincipal() {
        assertThat(rules("RULE:^CN=([^,]+),O=Acme$/$1/").principalFor("CN=x,O=Other")).isEmpty();
    }

    @Test
    void invalidRulesFailStartup() {
        assertThatThrownBy(() -> rules("NOT A RULE")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void identityWithoutCertificateIsLeftAsIs() {
        var oidc = QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal("alice")).addRole("g").build();
        var augmented = rules("DEFAULT").augment(oidc, null).await().indefinitely();
        assertThat(augmented).isSameAs(oidc);
        assertThat(Caller.of(augmented)).isEqualTo(new Caller("alice", java.util.Set.of("g"), false));
    }
}
