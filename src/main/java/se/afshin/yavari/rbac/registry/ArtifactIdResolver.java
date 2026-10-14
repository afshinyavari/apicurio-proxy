package se.afshin.yavari.rbac.registry;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import se.afshin.yavari.rbac.registry.RegistryRequest.IdLookup;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Finds the artifacts behind an id-only request by asking the registry, on the same API the
 * request came in on: core {@code search/versions}, ccompat {@code schemas/ids/{id}/versions}.
 * A content id (and a ccompat schema id) is shared by every artifact holding that content, so
 * the answer can name several artifacts.
 */
@ApplicationScoped
public class ArtifactIdResolver {

    private static final int PAGE_SIZE = 500;
    /** Upper bound on search pages per lookup, so one request cannot page without end. */
    private static final int MAX_PAGES = 20;
    private static final ObjectMapper JSON = new ObjectMapper();

    private final String apicurioUrl;
    private final int pageSize;
    private final HttpClient http = HttpClient.newHttpClient();

    @Inject
    public ArtifactIdResolver(@ConfigProperty(name = "proxy.apicurio.url") String apicurioUrl) {
        this(apicurioUrl, PAGE_SIZE);
    }

    /** Test seam: explicit page size. */
    ArtifactIdResolver(String apicurioUrl, int pageSize) {
        this.apicurioUrl = apicurioUrl.replaceAll("/$", "");
        this.pageSize = pageSize;
    }

    /** Distinct artifact ids holding the id, in registry order; empty when the id is unknown
     *  or the registry cannot be asked. */
    public List<String> resolve(IdLookup lookup) {
        Set<String> ids = new LinkedHashSet<>();
        try {
            switch (lookup.api()) {
                case CORE -> search(lookup.apiRoot() + "/search/versions?" + lookup.param() + "=" + lookup.id()
                        + "&orderby=globalId&order=asc", ids);
                case CCOMPAT -> {
                    JsonNode versions = get(lookup.apiRoot() + "/schemas/ids/" + lookup.id() + "/versions");
                    if (versions != null) collect(versions, "subject", ids);
                }
                case OTHER -> { }
            }
        } catch (Exception e) {
            return List.of();
        }
        return new ArrayList<>(ids);
    }

    /** Pages through a version search, collecting the artifact id of each row. */
    private void search(String pathAndQuery, Set<String> out) throws Exception {
        int offset = 0;
        for (int page = 0; page < MAX_PAGES; page++) {
            JsonNode result = get(pathAndQuery + "&limit=" + pageSize + "&offset=" + offset);
            if (result == null) return;
            int fetched = collect(result.path("versions"), "artifactId", out);
            offset += fetched;
            if (fetched == 0 || offset >= result.path("count").asInt(0)) return;
        }
    }

    private static int collect(JsonNode rows, String field, Set<String> out) {
        int n = 0;
        for (JsonNode row : rows) {
            n++;
            JsonNode value = row.get(field);
            if (value != null && value.isTextual()) out.add(value.asText());
        }
        return n;
    }

    /** Parsed body of a 200 response, {@code null} for any other status. */
    private JsonNode get(String pathAndQuery) throws Exception {
        HttpResponse<String> resp = http.send(
                HttpRequest.newBuilder(URI.create(apicurioUrl + pathAndQuery)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        return resp.statusCode() == 200 ? JSON.readTree(resp.body()) : null;
    }
}
