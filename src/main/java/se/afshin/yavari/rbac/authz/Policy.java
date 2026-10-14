package se.afshin.yavari.rbac.authz;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import se.afshin.yavari.rbac.security.Caller;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The policy file: each rule grants {@code actions} on {@code artifacts} to certificate
 * {@code principals} and to OIDC {@code groups}.
 *
 * <pre>
 * rules:
 *   - groups: [orders-team]
 *     principals: ["CN=ci-pipeline"]
 *     artifacts: [orders-value, orders-key]
 *     actions: [READ, WRITE]
 * </pre>
 *
 * A principal is the certificate's Kafka principal, written as in a Kafka ACL (an optional
 * {@code User:} prefix is accepted, a DN may contain spaces). {@code "*"} as artifact matches
 * every artifact. Unknown keys are rejected so a misspelt rule fails loudly.
 */
public record Policy(List<Rule> rules) {

    public static final String WILDCARD = "*";

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory())
            .enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);

    public static final Policy EMPTY = new Policy(List.of());

    public Policy {
        rules = rules == null ? List.of() : List.copyOf(rules);
    }

    public static Policy parse(byte[] yaml) throws IOException {
        Policy policy = YAML.readValue(yaml, Policy.class);
        if (policy == null) throw new IllegalArgumentException("policy file is empty");
        return policy;
    }

    public boolean allows(Caller caller, String artifact, Action action) {
        return rules.stream().anyMatch(rule -> rule.appliesTo(caller) && rule.grants(artifact, action));
    }

    public record Rule(Set<String> principals, Set<String> groups, Set<String> artifacts, Set<Action> actions) {

        public Rule {
            principals = principals == null ? Set.of()
                    : principals.stream().map(Rule::normalize).collect(Collectors.toUnmodifiableSet());
            groups = groups == null ? Set.of() : Set.copyOf(groups);
            artifacts = artifacts == null ? Set.of() : Set.copyOf(artifacts);
            actions = actions == null ? Set.of() : Set.copyOf(actions);
            if (principals.isEmpty() && groups.isEmpty()) {
                throw new IllegalArgumentException("a rule needs 'principals' or 'groups'");
            }
            if (artifacts.isEmpty() || actions.isEmpty()) {
                throw new IllegalArgumentException("a rule needs 'artifacts' and 'actions'");
            }
        }

        /** Principals name certificate callers only; OIDC callers are bound through their groups. */
        boolean appliesTo(Caller caller) {
            return (caller.certificate() && principals.contains(caller.name()))
                    || !Collections.disjoint(groups, caller.groups());
        }

        boolean grants(String artifact, Action action) {
            return actions.contains(action) && (artifacts.contains(WILDCARD) || artifacts.contains(artifact));
        }

        /** Drops a {@code User:} prefix and writes a DN in RFC 2253 form, as the certificate gives it. */
        static String normalize(String principal) {
            String p = principal.strip();
            if (p.startsWith("User:")) p = p.substring("User:".length()).strip();
            if (!p.contains("=")) return p;
            try {
                return new X500Principal(p).getName();
            } catch (IllegalArgumentException notADn) {
                return p;
            }
        }
    }
}
