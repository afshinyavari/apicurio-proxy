package se.afshin.yavari.rbac.registry;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import se.afshin.yavari.rbac.registry.RegistryRequest.Api;
import se.afshin.yavari.rbac.registry.RegistryRequest.IdLookup;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/** Runs the resolver against a local HTTP server that answers like the registry does. */
class ArtifactIdResolverTest {

    private HttpServer registry;
    private final Map<String, String> responses = new ConcurrentHashMap<>();
    private final List<String> requests = new CopyOnWriteArrayList<>();
    private volatile int status = 200;

    @BeforeEach
    void startRegistry() throws Exception {
        registry = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        registry.createContext("/", exchange -> {
            String uri = exchange.getRequestURI().toString();
            requests.add(uri);
            String body = responses.get(uri);
            byte[] bytes = (body == null ? "{}" : body).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(body == null ? 404 : status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        registry.start();
    }

    @AfterEach
    void stopRegistry() {
        registry.stop(0);
    }

    private ArtifactIdResolver resolver(int pageSize) {
        return new ArtifactIdResolver("http://localhost:" + registry.getAddress().getPort() + "/", pageSize);
    }

    private static String v3Versions(int count, String... artifactIds) {
        List<String> rows = new ArrayList<>();
        for (String id : artifactIds) rows.add("{\"artifactId\":\"" + id + "\",\"groupId\":\"g\",\"version\":\"1\"}");
        return "{\"count\":" + count + ",\"versions\":[" + String.join(",", rows) + "]}";
    }

    @Test
    void v3GlobalIdResolvesThroughVersionSearch() {
        responses.put("/apis/registry/v3/search/versions?globalId=7&orderby=globalId&order=asc&limit=500&offset=0",
                v3Versions(1, "orders-value"));
        assertThat(resolver(500).resolve(new IdLookup(Api.CORE, "/apis/registry/v3", "globalId", "7")))
                .containsExactly("orders-value");
    }

    @Test
    void v3ContentIdSharedByArtifactsResolvesToEachOnce() {
        responses.put("/apis/registry/v3/search/versions?contentId=3&orderby=globalId&order=asc&limit=500&offset=0",
                v3Versions(3, "payments-value", "payments-value", "refunds-value"));
        assertThat(resolver(500).resolve(new IdLookup(Api.CORE, "/apis/registry/v3", "contentId", "3")))
                .containsExactly("payments-value", "refunds-value");
    }

    @Test
    void v3ResultsBeyondOnePageAreFetched() {
        String base = "/apis/registry/v3/search/versions?contentId=3&orderby=globalId&order=asc&limit=2&offset=";
        responses.put(base + "0", v3Versions(5, "a-key", "b-key"));
        responses.put(base + "2", v3Versions(5, "c-key", "d-key"));
        responses.put(base + "4", v3Versions(5, "e-key"));
        assertThat(resolver(2).resolve(new IdLookup(Api.CORE, "/apis/registry/v3", "contentId", "3")))
                .containsExactly("a-key", "b-key", "c-key", "d-key", "e-key");
        assertThat(requests).hasSize(3);
    }

    @Test
    void ccompatResolvesToTheSubjectsUsingTheSchema() {
        responses.put("/apis/ccompat/v7/schemas/ids/6/versions",
                "[{\"subject\":\"shipments-value\",\"version\":1},{\"subject\":\"returns-value\",\"version\":3}]");
        assertThat(resolver(500).resolve(new IdLookup(Api.CCOMPAT, "/apis/ccompat/v7", "id", "6")))
                .containsExactly("shipments-value", "returns-value");
    }

    @Test
    void unknownIdResolvesToNothing() {
        responses.put("/apis/registry/v3/search/versions?globalId=99&orderby=globalId&order=asc&limit=500&offset=0",
                v3Versions(0));
        assertThat(resolver(500).resolve(new IdLookup(Api.CORE, "/apis/registry/v3", "globalId", "99"))).isEmpty();
        // ccompat answers 404 for an unknown schema id
        assertThat(resolver(500).resolve(new IdLookup(Api.CCOMPAT, "/apis/ccompat/v7", "id", "99"))).isEmpty();
    }

    @Test
    void registryErrorOrGarbageResolvesToNothing() {
        String uri = "/apis/registry/v3/search/versions?globalId=7&orderby=globalId&order=asc&limit=500&offset=0";
        responses.put(uri, "not json");
        assertThat(resolver(500).resolve(new IdLookup(Api.CORE, "/apis/registry/v3", "globalId", "7"))).isEmpty();
        responses.put(uri, v3Versions(1, "orders-value"));
        status = 500;
        assertThat(resolver(500).resolve(new IdLookup(Api.CORE, "/apis/registry/v3", "globalId", "7"))).isEmpty();
    }

    @Test
    void unreachableRegistryResolvesToNothing() {
        ArtifactIdResolver dead = new ArtifactIdResolver("http://localhost:1", 500);
        assertThat(dead.resolve(new IdLookup(Api.CORE, "/apis/registry/v3", "globalId", "7"))).isEmpty();
    }
}
