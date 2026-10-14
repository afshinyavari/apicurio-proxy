package se.afshin.yavari.rbac.registry;

import se.afshin.yavari.rbac.authz.Action;

/**
 * What a registry request is about: the artifact and action authorization is asked about.
 * {@code artifact} is {@code "*"} for registry-wide requests and whenever {@code lookup} is set.
 */
public record RegistryRequest(Api api, Action action, String artifact, IdLookup lookup) {

    public static final String WILDCARD = "*";

    /** The API a request addresses; decides id resolution and the error format. */
    public enum Api { CORE, CCOMPAT, OTHER }

    /** An id that names content rather than an artifact; resolved against the registry before
     *  authorization. {@code apiRoot} is the request's own API root, e.g. {@code /apis/registry/v3}. */
    public record IdLookup(Api api, String apiRoot, String param, String id) {}

    static RegistryRequest registryWide(Api api, Action action) {
        return new RegistryRequest(api, action, WILDCARD, null);
    }

    static RegistryRequest lookup(Api api, String apiRoot, Action action, String param, String id) {
        return new RegistryRequest(api, action, WILDCARD, new IdLookup(api, apiRoot, param, id));
    }
}
