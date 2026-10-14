package se.afshin.yavari.rbac.proxy;

import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.common.annotation.RunOnVirtualThread;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import se.afshin.yavari.rbac.authz.Authorizer;
import se.afshin.yavari.rbac.registry.ArtifactIdResolver;
import se.afshin.yavari.rbac.registry.RegistryErrors;
import se.afshin.yavari.rbac.registry.RegistryRequest;
import se.afshin.yavari.rbac.registry.RequestClassifier;
import se.afshin.yavari.rbac.security.Caller;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Authorizes every request and forwards the allowed ones to the registry unchanged. Each request
 * is recorded on the {@code audit} log category.
 */
@Path("{path: .*}")
@Authenticated
@Consumes(MediaType.WILDCARD)
@Produces(MediaType.WILDCARD)
public class ProxyResource {

    private static final Logger AUDIT = Logger.getLogger("audit");

    private static final Set<String> HOP_BY_HOP = Set.of(
        "connection", "content-length", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host"
    );

    @Inject SecurityIdentity identity;
    @Inject Authorizer authorizer;
    @Inject ArtifactIdResolver resolver;

    @ConfigProperty(name = "proxy.apicurio.url") String apicurioUrl;

    private final HttpClient http = HttpClient.newHttpClient();

    @GET
    @RunOnVirtualThread
    public Response get(@Context UriInfo uriInfo, @Context HttpHeaders headers) {
        return proxy("GET", uriInfo, headers, null);
    }

    @POST
    @RunOnVirtualThread
    public Response post(@Context UriInfo uriInfo, @Context HttpHeaders headers, byte[] body) {
        return proxy("POST", uriInfo, headers, body);
    }

    @PUT
    @RunOnVirtualThread
    public Response put(@Context UriInfo uriInfo, @Context HttpHeaders headers, byte[] body) {
        return proxy("PUT", uriInfo, headers, body);
    }

    @DELETE
    @RunOnVirtualThread
    public Response delete(@Context UriInfo uriInfo, @Context HttpHeaders headers) {
        return proxy("DELETE", uriInfo, headers, null);
    }

    private Response proxy(String method, UriInfo uriInfo, HttpHeaders headers, byte[] body) {
        long start = System.nanoTime();
        // The path stays percent-encoded end to end: the classifier decodes it per segment and
        // the registry receives exactly what the client sent.
        URI uri = uriInfo.getRequestUri();
        RegistryRequest request = RequestClassifier.classify(method, uri.getRawPath(), uri.getRawQuery(),
                headers.getHeaderString(HttpHeaders.CONTENT_TYPE), body);
        Caller caller = Caller.of(identity);

        // An id-only request is allowed when the caller may use any artifact holding that
        // content. An id the registry cannot resolve stays registry-wide ("*").
        List<String> artifacts = request.lookup() == null ? List.of() : resolver.resolve(request.lookup());
        if (artifacts.isEmpty()) artifacts = List.of(request.artifact());
        Optional<String> allowed = authorizer.firstAllowed(caller, artifacts, request.action());
        String artifact = allowed.orElse(artifacts.get(0));

        Response response = allowed.isPresent()
                ? forward(request, method, uri, headers, body)
                : RegistryErrors.forbidden(request.api(), request.action() + " on artifact '" + artifact
                        + "' is not permitted for " + caller.name());

        AUDIT.infof("principal=\"%s\" action=%s artifact=\"%s\" decision=%s status=%d latencyMs=%d",
                caller.name(), request.action(), artifact, allowed.isPresent() ? "allow" : "deny",
                response.getStatus(), (System.nanoTime() - start) / 1_000_000);
        return response;
    }

    private Response forward(RegistryRequest request, String method, URI uri, HttpHeaders headers, byte[] body) {
        try {
            String target = apicurioUrl.replaceAll("/$", "") + uri.getRawPath()
                    + (uri.getRawQuery() != null ? "?" + uri.getRawQuery() : "");
            HttpRequest.Builder upstream = HttpRequest.newBuilder(URI.create(target));
            headers.getRequestHeaders().forEach((name, values) -> {
                String lower = name.toLowerCase();
                if ("authorization".equals(lower) || HOP_BY_HOP.contains(lower)) return;
                values.forEach(v -> upstream.header(name, v));
            });
            upstream.method(method, body != null && body.length > 0
                    ? HttpRequest.BodyPublishers.ofByteArray(body)
                    : HttpRequest.BodyPublishers.noBody());

            HttpResponse<byte[]> answer = http.send(upstream.build(), HttpResponse.BodyHandlers.ofByteArray());

            Response.ResponseBuilder rb = Response.status(answer.statusCode());
            answer.headers().map().forEach((name, values) -> {
                // Skip HTTP/2 pseudo-headers (:status, :path, etc.) — invalid in HTTP/1 responses
                if (name.startsWith(":") || HOP_BY_HOP.contains(name.toLowerCase())) return;
                values.forEach(v -> rb.header(name, v));
            });
            byte[] respBody = answer.body();
            if (respBody != null && respBody.length > 0) rb.entity(respBody);
            return rb.build();
        } catch (Exception e) {
            return RegistryErrors.badGateway(request.api(), "Bad gateway: " + e.getMessage());
        }
    }
}
