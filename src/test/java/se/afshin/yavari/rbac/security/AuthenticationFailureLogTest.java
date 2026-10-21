package se.afshin.yavari.rbac.security;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.function.Predicate;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Requests without a valid identity are answered 401 before the proxy resource, and still get
 * an audit line. Tests run without TLS, so the certificate is always {@code none}; the smoke test
 * covers certificates.
 */
@QuarkusTest
class AuthenticationFailureLogTest {

    @Inject AuthenticationFailureLog log;

    private final List<String> lines = new CopyOnWriteArrayList<>();

    private final Handler capture = new Handler() {
        @Override public void publish(LogRecord record) {
            lines.add(record.getParameters() == null ? record.getMessage()
                    : String.format(record.getMessage(), record.getParameters()));
        }
        @Override public void flush() { }
        @Override public void close() { }
    };

    @BeforeEach
    void capture() {
        log.summarize();   // forget the sources earlier tests left
        Logger.getLogger("audit").addHandler(capture);
    }

    @AfterEach
    void release() {
        Logger.getLogger("audit").removeHandler(capture);
    }

    private long count(Predicate<String> line) {
        return lines.stream().filter(line).count();
    }

    private static boolean unauthenticated(String line) {
        return line.contains("decision=unauthenticated") && line.contains("request=");
    }

    /** Lines are written when the response has ended, which may be just after the client returns. */
    private void awaitLines(Predicate<String> line, long expected) throws InterruptedException {
        for (int i = 0; i < 50 && count(line) < expected; i++) Thread.sleep(20);
        assertThat(count(line)).as("lines in %s", lines).isEqualTo(expected);
    }

    private String unauthenticatedLine() throws InterruptedException {
        awaitLines(AuthenticationFailureLogTest::unauthenticated, 1);
        return lines.stream().filter(AuthenticationFailureLogTest::unauthenticated).findFirst().orElseThrow();
    }

    @Test
    void requestWithoutCredentialsIsLogged() throws InterruptedException {
        given().get("/apis/registry/v3/groups/default/artifacts/orders").then().statusCode(401);

        assertThat(unauthenticatedLine())
                .contains("request=\"GET /apis/registry/v3/groups/default/artifacts/orders\"")
                .contains("certificate=none token=no decision=unauthenticated status=401")
                .contains("reason=\"no client certificate and no bearer token\"")
                .containsPattern("client=\\S+:\\d+");
    }

    @Test
    void requestWithUnusableTokenIsLogged() throws InterruptedException {
        given().header("Authorization", "Bearer not-a-token")
                .delete("/apis/registry/v3/groups/default/artifacts/orders").then().statusCode(401);

        assertThat(unauthenticatedLine())
                .contains("request=\"DELETE /apis/registry/v3/groups/default/artifacts/orders\"")
                .contains("certificate=none token=yes decision=unauthenticated status=401");
    }

    @Test
    void repeatsAreSummarizedAndCountingStartsOver() throws InterruptedException {
        for (int i = 0; i < 3; i++) {
            given().get("/apis/registry/v3/groups/default/artifacts/orders-" + i).then().statusCode(401);
        }
        Thread.sleep(200);
        awaitLines(AuthenticationFailureLogTest::unauthenticated, 1);

        log.summarize();
        assertThat(lines).anyMatch(line -> line.contains("certificate=none token=no decision=unauthenticated status=401 "
                + "reason=\"no client certificate and no bearer token\" repeated=2 in=60s"));

        given().get("/apis/registry/v3/groups/default/artifacts/orders").then().statusCode(401);
        awaitLines(AuthenticationFailureLogTest::unauthenticated, 2);
    }

    @Test
    void noSummaryWithoutRepeats() throws InterruptedException {
        given().get("/apis/registry/v3/groups/default/artifacts/orders").then().statusCode(401);
        unauthenticatedLine();
        log.summarize();
        assertThat(lines).noneMatch(line -> line.contains("repeated="));
    }

    @Test
    void healthIsNotLogged() {
        given().get("/q/health/live").then().statusCode(200);
        assertThat(lines).noneMatch(line -> line.contains("decision=unauthenticated"));
    }
}
