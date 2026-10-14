package se.afshin.yavari.rbac.registry;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import se.afshin.yavari.rbac.registry.RegistryRequest.Api;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Error responses the proxy itself produces, in the format of the API the request addressed.
 * The registry's clients parse error bodies: the v3 SDK fails on a body it cannot read, and
 * Confluent clients expect a Schema Registry {@code error_code}.
 */
public final class RegistryErrors {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String CCOMPAT_JSON = "application/vnd.schemaregistry.v1+json";

    private RegistryErrors() {}

    public static Response forbidden(Api api, String detail) {
        return response(api, 403, "Forbidden", "ForbiddenException", detail);
    }

    public static Response badGateway(Api api, String detail) {
        return response(api, 502, "Bad Gateway", "BadGatewayException", detail);
    }

    private static Response response(Api api, int status, String title, String name, String detail) {
        Map<String, Object> body = new LinkedHashMap<>();
        switch (api) {
            case CORE -> {
                body.put("detail", detail);
                body.put("title", title);
                body.put("status", status);
                body.put("name", name);
            }
            case CCOMPAT -> {
                // Schema Registry convention: HTTP status followed by a two-digit sub-code.
                body.put("error_code", status * 100 + 1);
                body.put("message", detail);
            }
            case OTHER -> {
                return Response.status(status).type("text/plain").entity(detail).build();
            }
        }
        try {
            return Response.status(status).type(api == Api.CCOMPAT ? CCOMPAT_JSON : "application/json")
                    .entity(JSON.writeValueAsString(body)).build();
        } catch (JsonProcessingException e) {
            return Response.status(status).type("text/plain").entity(detail).build();
        }
    }
}
