package se.afshin.yavari.rbac.proxy;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.SecurityAttribute;
import io.quarkus.test.security.TestSecurity;
import jakarta.inject.Inject;
import org.apache.kafka.common.acl.AccessControlEntry;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.acl.AclPermissionType;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import org.junit.jupiter.api.Test;
import se.afshin.yavari.rbac.authz.kafka.KafkaAclStore;

import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

/**
 * End to end through HTTP. The registry is unreachable in tests, so an allowed request answers
 * 502 and a denied one 403. {@code @TestSecurity} identities skip the augmentors, so certificate
 * callers carry the attribute {@code CertificatePrincipalAugmentor} would set.
 */
@QuarkusTest
class ProxyResourceTest {

    private static final String CERTIFICATE = "proxy.certificate-principal";

    @Inject KafkaAclStore aclStore;

    private void acls(AclBinding... bindings) {
        aclStore.update(List.of(bindings));
    }

    private static AclBinding topicAcl(String principal, String topic, AclOperation op, AclPermissionType perm) {
        return new AclBinding(new ResourcePattern(ResourceType.TOPIC, topic, PatternType.LITERAL),
                new AccessControlEntry("User:" + principal, "*", op, perm));
    }

    // ── OIDC callers: groups → policy file ───────────────────────────────────

    @Test
    @TestSecurity(user = "alice", roles = {"orders-team"})
    void groupIsAllowedItsArtifactsOnly() {
        given().get("/apis/registry/v3/groups/default/artifacts/orders").then().statusCode(502);
        given().get("/apis/registry/v3/groups/default/artifacts/invoices").then().statusCode(403);
        given().delete("/apis/registry/v3/groups/default/artifacts/orders").then().statusCode(403);
    }

    @Test
    @TestSecurity(user = "schemadmin", roles = {"schema-admin"})
    void wildcardGroupIsAllowedEverything() {
        given().get("/apis/registry/v3/groups/default/artifacts/invoices").then().statusCode(502);
        given().get("/apis/registry/v3/system/info").then().statusCode(502);
    }

    @Test
    @TestSecurity(user = "alice", roles = {"orders-team"})
    void unresolvableIdNeedsWildcard() {
        // The registry cannot resolve globalId 7, so the request stays registry-wide.
        given().get("/apis/registry/v3/ids/globalIds/7").then().statusCode(403);
    }

    @Test
    @TestSecurity(user = "schemadmin", roles = {"schema-admin"})
    void unresolvableIdIsAllowedForWildcard() {
        given().get("/apis/registry/v3/ids/globalIds/7").then().statusCode(502);
    }

    // ── certificate callers: Kafka ACLs (+ policy principals) ─────────────────

    @Test
    @TestSecurity(user = "CN=orders-service", attributes = @SecurityAttribute(key = CERTIFICATE, value = "true"))
    void writeAclAllowsItsTopicsSubjectsOnly() {
        acls(topicAcl("CN=orders-service", "orders", AclOperation.WRITE, AclPermissionType.ALLOW));
        given().body("{}").contentType("application/json")
            .put("/apis/registry/v3/groups/default/artifacts/orders-value").then().statusCode(502);
        given().get("/apis/registry/v3/groups/default/artifacts/invoices-value").then().statusCode(403);
    }

    @Test
    @TestSecurity(user = "CN=orders-service", attributes = @SecurityAttribute(key = CERTIFICATE, value = "true"))
    void createIsAuthorizedOnTheArtifactIdInTheBody() {
        acls(topicAcl("CN=orders-service", "orders", AclOperation.WRITE, AclPermissionType.ALLOW));
        given().body("{\"artifactId\":\"orders-value\",\"artifactType\":\"AVRO\"}").contentType("application/json")
            .post("/apis/registry/v3/groups/default/artifacts?ifExists=FIND_OR_CREATE_VERSION").then().statusCode(502);
        given().body("{\"artifactId\":\"invoices-value\",\"artifactType\":\"AVRO\"}").contentType("application/json")
            .post("/apis/registry/v3/groups/default/artifacts").then().statusCode(403);
        // No artifact id in the body: the registry would pick one, so this is registry-wide.
        given().body("{}").contentType("application/json")
            .post("/apis/registry/v3/groups/default/artifacts").then().statusCode(403);
    }

    @Test
    @TestSecurity(user = "CN=orders-reader", attributes = @SecurityAttribute(key = CERTIFICATE, value = "true"))
    void searchByContentNeedsOnlyRead() {
        acls(topicAcl("CN=orders-reader", "orders", AclOperation.READ, AclPermissionType.ALLOW));
        given().body("{}").contentType("application/json")
            .post("/apis/registry/v3/search/versions?artifactId=orders-value&groupId=default").then().statusCode(502);
        given().body("{}").contentType("application/json")
            .post("/apis/registry/v3/search/versions?artifactId=invoices-value&groupId=default").then().statusCode(403);
    }

    @Test
    @TestSecurity(user = "CN=orders-service", attributes = @SecurityAttribute(key = CERTIFICATE, value = "true"))
    void kafkaDenyWins() {
        acls(topicAcl("*", "*", AclOperation.ALL, AclPermissionType.ALLOW),
             topicAcl("CN=orders-service", "orders", AclOperation.ALL, AclPermissionType.DENY));
        given().get("/apis/registry/v3/groups/default/artifacts/orders-value").then().statusCode(403);
    }

    @Test
    @TestSecurity(user = "CN=orders-service", roles = {"orders-team"},
                  attributes = @SecurityAttribute(key = CERTIFICATE, value = "true"))
    void certificateCallerIgnoresGroups() {
        acls();
        given().get("/apis/registry/v3/groups/default/artifacts/orders").then().statusCode(403);
    }

    @Test
    @TestSecurity(user = "CN=payments-app", attributes = @SecurityAttribute(key = CERTIFICATE, value = "true"))
    void policyPrincipalGrantsWithoutAcls() {
        acls();
        given().get("/apis/registry/v3/groups/default/artifacts/invoices").then().statusCode(502);
        given().get("/apis/registry/v3/groups/default/artifacts/orders").then().statusCode(403);
    }

    // ── ccompat (Confluent serdes): subject = artifact ────────────────────────

    @Test
    @TestSecurity(user = "CN=orders-service", attributes = @SecurityAttribute(key = CERTIFICATE, value = "true"))
    void ccompatRegisterIsAuthorizedOnTheSubject() {
        acls(topicAcl("CN=orders-service", "orders", AclOperation.WRITE, AclPermissionType.ALLOW));
        given().body("{\"schema\":\"{}\"}").contentType("application/vnd.schemaregistry.v1+json")
            .post("/apis/ccompat/v7/subjects/orders-value/versions").then().statusCode(502);
        given().body("{\"schema\":\"{}\"}").contentType("application/vnd.schemaregistry.v1+json")
            .post("/apis/ccompat/v7/subjects/invoices-value/versions").then().statusCode(403);
    }

    @Test
    @TestSecurity(user = "CN=orders-reader", attributes = @SecurityAttribute(key = CERTIFICATE, value = "true"))
    void ccompatSchemaLookupNeedsOnlyRead() {
        acls(topicAcl("CN=orders-reader", "orders", AclOperation.READ, AclPermissionType.ALLOW));
        given().body("{\"schema\":\"{}\"}").contentType("application/vnd.schemaregistry.v1+json")
            .post("/apis/ccompat/v7/subjects/orders-value").then().statusCode(502);
        given().body("{\"schema\":\"{}\"}").contentType("application/vnd.schemaregistry.v1+json")
            .post("/apis/ccompat/v7/subjects/orders-value/versions").then().statusCode(403);
    }

    @Test
    @TestSecurity(user = "CN=orders-service", attributes = @SecurityAttribute(key = CERTIFICATE, value = "true"))
    void ccompatSchemaIdIsNotAuthorizedByTheSubjectHint() {
        acls(topicAcl("CN=orders-service", "orders", AclOperation.WRITE, AclPermissionType.ALLOW));
        given().get("/apis/ccompat/v7/schemas/ids/7?subject=orders-value").then().statusCode(403);
    }

    // ── denials are answered in the registry's own error format ───────────────

    @Test
    @TestSecurity(user = "alice", roles = {"orders-team"})
    void coreDenialIsAProblemDetailsDocument() {
        given().get("/apis/registry/v3/groups/default/artifacts/invoices")
            .then().statusCode(403).contentType("application/json")
            .body("status", is(403))
            .body("title", is("Forbidden"))
            .body("detail", is("READ on artifact 'invoices' is not permitted for alice"));
    }

    @Test
    @TestSecurity(user = "alice", roles = {"orders-team"})
    void ccompatDenialUsesSchemaRegistryErrorCode() {
        given().get("/apis/ccompat/v7/subjects/invoices/versions/latest")
            .then().statusCode(403).contentType("application/vnd.schemaregistry.v1+json")
            .body("error_code", is(40301));
    }

    @Test
    @TestSecurity(user = "alice", roles = {"orders-team"})
    void upstreamFailureIsABadGatewayInTheApiFormat() {
        given().get("/apis/registry/v3/groups/default/artifacts/orders")
            .then().statusCode(502).body("status", is(502)).body("detail", not(""));
    }

    @Test
    void anonymousIsUnauthorized() {
        given().get("/apis/registry/v3/groups/default/artifacts/orders").then().statusCode(401);
    }
}
