package se.afshin.yavari.rbac.security;

import io.quarkus.scheduler.Scheduled;
import io.quarkus.security.spi.runtime.AuthenticationFailureEvent;
import io.quarkus.vertx.http.runtime.filters.Filters;
import io.quarkus.vertx.http.runtime.security.SecurityHandlerPriorities;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Records every request answered 401 on the {@code audit} log category. These requests never
 * reach the proxy resource: no client certificate and no token, a certificate no mapping rule
 * matches, or a rejected token. The line names the client, the request, the certificate subject
 * if one was presented and why authentication failed.
 *
 * <p>A client that keeps retrying would fill the log, so a source (client address, certificate,
 * token, reason) gets one line when it first fails; its repeats are counted and summarized once
 * per {@code proxy.audit.repeat-summary-interval}, after which it starts over. At DEBUG every
 * repeat is logged as well.
 */
@ApplicationScoped
public class AuthenticationFailureLog {

    private static final Logger AUDIT = Logger.getLogger("audit");

    private static final String REASON = AuthenticationFailureLog.class.getName() + ".reason";

    /** What makes two failures the same; the request path is left out, a retrying client varies it. */
    record Source(String client, String certificate, String token, String reason) { }

    private final Map<Source, AtomicInteger> repeats = new ConcurrentHashMap<>();

    @ConfigProperty(name = "proxy.audit.repeat-summary-interval") String interval;

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

    /** One line per source that failed again since it was first logged; the counting starts over. */
    @Scheduled(every = "${proxy.audit.repeat-summary-interval}", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void summarize() {
        for (Source source : repeats.keySet()) {
            int count = repeats.remove(source).get();
            if (count == 0) continue;
            AUDIT.infof("client=%s certificate=%s token=%s decision=unauthenticated status=401 reason=\"%s\" repeated=%d in=%s",
                    source.client(), source.certificate(), source.token(), source.reason(), count, interval);
        }
    }

    private void log(RoutingContext ctx) {
        HttpServerRequest request = ctx.request();
        String subject = subject(request);
        boolean token = request.getHeader(HttpHeaders.AUTHORIZATION) != null;
        String reason = ctx.get(REASON);
        if (reason == null) {
            reason = subject == null && !token ? "no client certificate and no bearer token" : "not authenticated";
        }
        Source source = new Source(request.remoteAddress().hostAddress(),
                subject == null ? "none" : "\"" + subject + "\"", token ? "yes" : "no", reason);

        AtomicInteger seen = repeats.putIfAbsent(source, new AtomicInteger());
        if (seen != null) seen.incrementAndGet();
        AUDIT.logf(seen == null ? Logger.Level.INFO : Logger.Level.DEBUG,
                "client=%s request=\"%s %s\" certificate=%s token=%s decision=unauthenticated status=401 reason=\"%s\"",
                request.remoteAddress(), request.method(), request.path(),
                source.certificate(), source.token(), source.reason());
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
