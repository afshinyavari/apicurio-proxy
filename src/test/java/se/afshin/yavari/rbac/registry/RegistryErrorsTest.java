package se.afshin.yavari.rbac.registry;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import se.afshin.yavari.rbac.registry.RegistryRequest.Api;

import static org.assertj.core.api.Assertions.assertThat;

/** Error bodies mirror the registry's own format per API, so its clients can parse them. */
class RegistryErrorsTest {

    private static JsonNode json(Response r) throws Exception {
        return new ObjectMapper().readTree((String) r.getEntity());
    }

    @Test
    void v3ErrorIsAProblemDetailsDocument() throws Exception {
        Response r = RegistryErrors.forbidden(Api.CORE, "WRITE on artifact 'orders-value' is not permitted");
        assertThat(r.getStatus()).isEqualTo(403);
        assertThat(r.getMediaType().toString()).isEqualTo("application/json");
        JsonNode body = json(r);
        assertThat(body.get("status").asInt()).isEqualTo(403);
        assertThat(body.get("title").asText()).isEqualTo("Forbidden");
        assertThat(body.get("detail").asText()).isEqualTo("WRITE on artifact 'orders-value' is not permitted");
        assertThat(body.get("name").asText()).isEqualTo("ForbiddenException");
    }

    @Test
    void ccompatErrorUsesSchemaRegistryErrorCode() throws Exception {
        Response r = RegistryErrors.forbidden(Api.CCOMPAT, "denied");
        assertThat(r.getStatus()).isEqualTo(403);
        assertThat(r.getMediaType().toString()).isEqualTo("application/vnd.schemaregistry.v1+json");
        JsonNode body = json(r);
        assertThat(body.get("error_code").asInt()).isEqualTo(40301);
        assertThat(body.get("message").asText()).isEqualTo("denied");
    }

    @Test
    void otherPathsGetPlainText() {
        Response r = RegistryErrors.forbidden(Api.OTHER, "denied");
        assertThat(r.getStatus()).isEqualTo(403);
        assertThat(r.getMediaType().toString()).isEqualTo("text/plain");
        assertThat(r.getEntity()).isEqualTo("denied");
    }

    @Test
    void badGatewayKeepsTheApiFormat() throws Exception {
        Response v3 = RegistryErrors.badGateway(Api.CORE, "connection refused");
        assertThat(v3.getStatus()).isEqualTo(502);
        assertThat(json(v3).get("status").asInt()).isEqualTo(502);
        assertThat(json(v3).get("detail").asText()).isEqualTo("connection refused");
        assertThat(json(RegistryErrors.badGateway(Api.CCOMPAT, "connection refused")).get("error_code").asInt())
                .isEqualTo(50201);
    }
}
