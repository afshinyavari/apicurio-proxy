package se.afshin.yavari.rbac.registry;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadFeature;
import se.afshin.yavari.rbac.authz.Action;
import se.afshin.yavari.rbac.registry.RegistryRequest.Api;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static se.afshin.yavari.rbac.registry.RegistryRequest.lookup;
import static se.afshin.yavari.rbac.registry.RegistryRequest.registryWide;

/**
 * Maps an HTTP request to the {@link RegistryRequest} authorization is asked about.
 *
 * <p>Understood are Apicurio's core API v3 ({@code /apis/registry/v3}) and the
 * Confluent-compatible API ({@code /apis/ccompat/vN}, subject = artifact). Every other path is
 * registry-wide. Whenever the artifact cannot be told with certainty (repeated parameters,
 * duplicate JSON keys, malformed input) the request is registry-wide, never the more specific
 * reading.
 */
public final class RequestClassifier {

    /** Rejects duplicate keys: the registry keeps the last one, so the first must not be trusted. */
    private static final JsonFactory STRICT_JSON =
            JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();

    private RequestClassifier() {}

    /**
     * @param rawPath  request path as received, still percent-encoded
     * @param rawQuery query string as received, or {@code null}
     */
    public static RegistryRequest classify(String method, String rawPath, String rawQuery,
                                           String contentType, byte[] body) {
        String verb = method.toUpperCase();
        Action action = actionFor(verb);
        List<String> seg;
        Map<String, List<String>> query;
        try {
            seg = segments(rawPath);
            query = queryParams(rawQuery);
        } catch (IllegalArgumentException malformedEncoding) {
            return registryWide(Api.OTHER, action);
        }

        if (seg.size() >= 3 && "apis".equals(seg.get(0))) {
            String root = "/apis/" + seg.get(1) + "/" + seg.get(2);
            List<String> rest = seg.subList(3, seg.size());
            if ("registry".equals(seg.get(1)) && "v3".equals(seg.get(2))) {
                return core(root, verb, action, rest, query, contentType, body);
            }
            if ("ccompat".equals(seg.get(1)) && seg.get(2).matches("v[0-9]+")) {
                return ccompat(root, verb, action, rest, query);
            }
        }
        return registryWide(Api.OTHER, action);
    }

    private static RegistryRequest core(String root, String verb, Action action, List<String> rest,
                                        Map<String, List<String>> query, String contentType, byte[] body) {
        Api api = Api.CORE;
        String head = rest.isEmpty() ? "" : rest.get(0);
        switch (head) {
            case "groups" -> {
                // groups/{group}/artifacts[/{artifact}/…]
                if (rest.size() >= 4 && "artifacts".equals(rest.get(2))) {
                    return new RegistryRequest(api, action, rest.get(3), null);
                }
                if (rest.size() == 3 && "artifacts".equals(rest.get(2)) && "POST".equals(verb)) {
                    String id = createdArtifactId(contentType, body);
                    return id != null ? new RegistryRequest(api, action, id, null) : registryWide(api, action);
                }
            }
            case "ids" -> {
                // ids/{globalIds|contentIds}/{id}[/references]
                if (rest.size() >= 3 && isNumber(rest.get(2))) {
                    String param = switch (rest.get(1)) {
                        case "globalIds" -> "globalId";
                        case "contentIds" -> "contentId";
                        default -> null;
                    };
                    if (param != null) return lookup(api, root, action, param, rest.get(2));
                }
            }
            case "search" -> {
                // A POST search carries content to look for; it changes nothing.
                Action searchAction = "POST".equals(verb) ? Action.READ : action;
                if (rest.size() == 2 && ("artifacts".equals(rest.get(1)) || "versions".equals(rest.get(1)))) {
                    // Filters on the exact artifact id, so the result cannot name another artifact.
                    String artifactId = single(query, "artifactId");
                    if (artifactId != null) return new RegistryRequest(api, searchAction, artifactId, null);
                    for (String param : List.of("globalId", "contentId")) {
                        String id = single(query, param);
                        if (id != null && isNumber(id)) return lookup(api, root, searchAction, param, id);
                    }
                }
                return registryWide(api, searchAction);
            }
            default -> { }
        }
        return registryWide(api, action);
    }

    private static RegistryRequest ccompat(String root, String verb, Action action, List<String> rest,
                                           Map<String, List<String>> query) {
        Api api = Api.CCOMPAT;
        boolean post = "POST".equals(verb);
        String head = rest.isEmpty() ? "" : rest.get(0);
        switch (head) {
            case "subjects" -> {
                // POST subjects/{subject} looks a schema up; POST subjects/{subject}/versions registers one.
                if (rest.size() >= 2) {
                    Action a = post && rest.size() == 2 ? Action.READ : action;
                    return new RegistryRequest(api, a, rest.get(1), null);
                }
            }
            case "schemas" -> {
                // The ?subject= hint is not enforced by the registry, so the id is resolved instead.
                if (rest.size() >= 3 && "ids".equals(rest.get(1)) && isNumber(rest.get(2))) {
                    return lookup(api, root, action, "id", rest.get(2));
                }
            }
            case "compatibility" -> {
                if (rest.size() >= 3 && "subjects".equals(rest.get(1))) {
                    return new RegistryRequest(api, post ? Action.READ : action, rest.get(2), null);
                }
            }
            case "config", "mode" -> {
                if (rest.size() >= 2) return new RegistryRequest(api, action, rest.get(1), null);
            }
            case "associations" -> {
                // associations/resources/{namespace}/{topic}?associationType=value|key
                String type = single(query, "associationType");
                if (rest.size() == 4 && "resources".equals(rest.get(1))
                        && ("value".equals(type) || "key".equals(type))) {
                    return new RegistryRequest(api, action, rest.get(3) + "-" + type, null);
                }
            }
            default -> { }
        }
        return registryWide(api, action);
    }

    static Action actionFor(String verb) {
        return switch (verb) {
            case "GET", "HEAD" -> Action.READ;
            case "DELETE"      -> Action.DELETE;
            default            -> Action.WRITE;
        };
    }

    /** Top-level {@code artifactId} of a {@code CreateArtifact} JSON body, or {@code null} when it
     *  is absent, not a non-empty string, or the body is not one well-formed JSON object. */
    private static String createdArtifactId(String contentType, byte[] body) {
        if (body == null || !isJson(contentType)) return null;
        try (JsonParser p = STRICT_JSON.createParser(body)) {
            if (p.nextToken() != JsonToken.START_OBJECT) return null;
            String id = null;
            while (p.nextToken() == JsonToken.FIELD_NAME) {
                String name = p.currentName();
                JsonToken value = p.nextToken();
                if ("artifactId".equals(name)) {
                    if (value != JsonToken.VALUE_STRING) return null;
                    id = p.getText();
                } else {
                    p.skipChildren();
                }
            }
            if (p.currentToken() != JsonToken.END_OBJECT || p.nextToken() != null) return null;
            return blankToNull(id);
        } catch (IOException malformed) {
            return null;
        }
    }

    private static boolean isJson(String contentType) {
        if (contentType == null) return false;
        int params = contentType.indexOf(';');
        String mediaType = params < 0 ? contentType : contentType.substring(0, params);
        return "application/json".equalsIgnoreCase(mediaType.trim());
    }

    /** Path segments, each percent-decoded on its own so an encoded slash stays inside its segment. */
    private static List<String> segments(String rawPath) {
        String path = rawPath.startsWith("/") ? rawPath.substring(1) : rawPath;
        List<String> out = new ArrayList<>();
        for (String s : path.split("/", -1)) {
            out.add(URLDecoder.decode(s.replace("+", "%2B"), StandardCharsets.UTF_8));
        }
        if (out.size() > 1 && out.get(out.size() - 1).isEmpty()) out.remove(out.size() - 1);
        return out;
    }

    private static Map<String, List<String>> queryParams(String rawQuery) {
        Map<String, List<String>> out = new HashMap<>();
        if (rawQuery == null || rawQuery.isEmpty()) return out;
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            String key = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
            String value = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            out.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
        }
        return out;
    }

    /** The parameter's value when it occurs exactly once and is not blank, else {@code null}. */
    private static String single(Map<String, List<String>> query, String name) {
        List<String> values = query.get(name);
        return values != null && values.size() == 1 ? blankToNull(values.get(0)) : null;
    }

    private static boolean isNumber(String s) {
        return s.matches("[0-9]{1,19}");
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s;
    }
}
