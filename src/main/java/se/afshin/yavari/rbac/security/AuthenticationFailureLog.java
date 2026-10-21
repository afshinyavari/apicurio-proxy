package se.afshin.yavari.rbac.security;

import io.quarkus.security.spi.runtime.AuthenticationFailureEvent;
import io.quarkus.vertx.http.runtime.filters.Filters;
import io.quarkus.vertx.http.runtime.security.SecurityHandlerPriorities;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import org.jboss.logging.Logger;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Records every request answered 401 on the {@code audit} log category. These requests never
 * reach the proxy resource: no client certificate and no token, a certificate no mapping rule
 * matches, or a rejected token. The line names the client, the request, the certificate subject
 * if one was presented and why authentication failed.
 */
@ApplicationScoped
public class AuthenticationFailureLog {

    private static final Logger AUDIT = Logger.getLogger("audit");

    private static final String REASON = AuthenticationFailureLog.class.getName() + ".reason";

    /** Runs before authentication, so the line is written whichever step answers 401. */
    void register(@Observes Filters filters) {
        filters.register(ctx -> {
            ctx.addEndHandler(ended -> {
                if (ctx.response().getStatusCode() == 401) log(ctx);
            });
            ctx.next();
        }, SecurityHandlerPriorities.AUTHENTICATION + 1);
    }

    /** Keeps the failure of a presented credential for the line; a missing one fires no event. */
    void failed(@Observes AuthenticationFailureEvent event) {
        if (event.getEventProperties().get(RoutingContext.class.getName()) instanceof RoutingContext ctx) {
            Throwable failure = event.getAuthenticationFailure();
            ctx.put(REASON, failure.getMessage() != null ? failure.getMessage() : failure.getClass().getSimpleName());
        }
    }

    private static void log(RoutingContext ctx) {
        HttpServerRequest request = ctx.request();
        String subject = subject(request);
        boolean token = request.getHeader(HttpHeaders.AUTHORIZATION) != null;
        String reason = ctx.get(REASON);
        if (reason == null) {
            reason = subject == null && !token ? "no client certificate and no bearer token" : "not authenticated";
        }
        AUDIT.infof("client=%s request=\"%s %s\" certificate=%s token=%s decision=unauthenticated status=401 reason=\"%s\"",
                request.remoteAddress(), request.method(), request.path(),
                subject == null ? "none" : "\"" + subject + "\"", token ? "yes" : "no", reason);
    }

    /** The RFC 2253 subject of the client certificate; null without one. */
    private static String subject(HttpServerRequest request) {
        SSLSession session = request.isSSL() ? request.sslSession() : null;
        if (session == null) return null;
        try {
            Certificate[] chain = session.getPeerCertificates();
            return chain.length > 0 && chain[0] instanceof X509Certificate certificate
                    ? certificate.getSubjectX500Principal().getName() : null;
        } catch (SSLPeerUnverifiedException noCertificate) {
            return null;
        }
    }
}
