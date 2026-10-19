package io.kestra.plugin.snyk;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.common.FetchType;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.serializers.FileSerde;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.*;

@KestraTest(startWorker = false)
@WireMockTest(httpPort = 18089)
class ListIssuesTest {
    private static final String BASE_URL = "http://localhost:18089/rest";
    private static final String PATH = "/rest/orgs/org-id/issues";

    @Inject
    RunContextFactory runContextFactory;

    @Test
    void fetchPaginatesAndAppliesSeverityFilter() throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
            .withQueryParam("version", equalTo("2024-10-15"))
            .withQueryParam("effective_severity_level", equalTo("critical,high"))
            .withQueryParam("limit", equalTo("100"))
            .withHeader("Authorization", equalTo("token test-token"))
            .withHeader("Accept", equalTo("application/vnd.api+json"))
            .willReturn(okJson("""
                {
                  "data": [{"id":"issue-1","type":"issue","attributes":{"effective_severity_level":"critical"}}],
                  "links": {"next":{"href":"http://localhost:18089/rest/orgs/org-id/issues?version=2024-10-15&starting_after=cursor-1"}}
                }
                """)));

        stubFor(get(urlPathEqualTo(PATH))
            .withQueryParam("starting_after", equalTo("cursor-1"))
            .willReturn(okJson("""
                {"data":[{"id":"issue-2","type":"issue","attributes":{"effective_severity_level":"high"}}],"links":{}}
                """)));

        var task = task(FetchType.FETCH, true);
        var output = task.run(runContextFactory.of());

        assertEquals(2L, output.getSize());
        assertEquals(2, output.getRows().size());
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void rootRelativePaginationLinkKeepsConfiguredRestBasePath() throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
            .inScenario("relative-pagination")
            .whenScenarioStateIs(Scenario.STARTED)
            .willReturn(okJson("""
                {
                  "data": [{"id":"relative-page-1","type":"issue"}],
                  "links": {"next":{"href":"/orgs/org-id/issues?version=2024-10-15&starting_after=cursor-relative"}}
                }
                """))
            .willSetStateTo("relative-page-2"));

        stubFor(get(urlPathEqualTo(PATH))
            .withQueryParam("starting_after", equalTo("cursor-relative"))
            .inScenario("relative-pagination")
            .whenScenarioStateIs("relative-page-2")
            .willReturn(okJson("""
                {"data":[{"id":"relative-page-2","type":"issue"}],"links":{}}
                """)));

        var output = task(FetchType.FETCH, false).run(runContextFactory.of());

        assertEquals(2L, output.getSize());
        assertEquals(2, output.getRows().size());
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
        verify(1, getRequestedFor(urlPathEqualTo(PATH)).withQueryParam("starting_after", equalTo("cursor-relative")));
    }

    @Test
    void fetchOneStopsAtFirstIssue() throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
            .willReturn(okJson("""
                {
                  "data": [{"id":"issue-1","type":"issue"},{"id":"issue-2","type":"issue"}],
                  "links": {"next":"http://localhost:18089/rest/orgs/org-id/issues?version=2024-10-15&starting_after=cursor-1"}
                }
                """)));

        var output = task(FetchType.FETCH_ONE, false).run(runContextFactory.of());

        assertEquals(1L, output.getSize());
        assertEquals("issue-1", output.getRow().get("id"));
        verify(1, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void storeWritesAllPagesAndReturnsReadableRows() throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
            .willReturn(okJson("""
                {"data":[{"id":"issue-1","type":"issue"}],"links":{"next":"http://localhost:18089/rest/orgs/org-id/issues?version=2024-10-15&starting_after=cursor-store"}}
                """)));

        stubFor(get(urlPathEqualTo(PATH))
            .withQueryParam("starting_after", equalTo("cursor-store"))
            .willReturn(okJson("""
                {"data":[{"id":"issue-2","type":"issue"}],"links":{}}
                """)));

        var runContext = runContextFactory.of();
        var output = task(FetchType.STORE, false).run(runContext);

        assertEquals(2L, output.getSize());
        assertNotNull(output.getUri());
        assertNull(output.getRows());

        try (var stored = runContext.storage().getFile(output.getUri())) {
            var rows = FileSerde.readAll(stored).collectList().block();
            assertNotNull(rows);
            assertEquals(2, rows.size());
            assertEquals("issue-1", ((Map<?, ?>) rows.getFirst()).get("id"));
            assertEquals("issue-2", ((Map<?, ?>) rows.get(1)).get("id"));
        }
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void emptyResultsReturnZeroRows() throws Exception {
        stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson("{\"data\":[],\"links\":{}}")));

        var output = task(FetchType.FETCH, false).run(runContextFactory.of());

        assertEquals(0L, output.getSize());
        assertTrue(output.getRows().isEmpty());
    }

    @Test
    void authenticationErrorsAreActionableAndDoNotExposeToken() {
        stubFor(get(urlPathEqualTo(PATH)).willReturn(aResponse().withStatus(401).withBody("unauthorized")));
        var error = assertThrows(IllegalStateException.class,
            () -> task(FetchType.FETCH, false).run(runContextFactory.of()));

        assertTrue(error.getMessage().contains("Authentication/authorization failed"));
        assertFalse(error.getMessage().contains("test-token"));
    }

    @Test
    void noneModeCountsAcrossPagesWithoutReturningRows() throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
            .willReturn(okJson("""
                {"data":[{"id":"issue-1","type":"issue"}],"links":{"next":"http://localhost:18089/rest/orgs/org-id/issues?version=2024-10-15&starting_after=cursor-none"}}
                """)));
        stubFor(get(urlPathEqualTo(PATH))
            .withQueryParam("starting_after", equalTo("cursor-none"))
            .willReturn(okJson("""
                {"data":[{"id":"issue-2","type":"issue"}],"links":{}}
                """)));

        var output = task(FetchType.NONE, false).run(runContextFactory.of());

        assertEquals(2L, output.getSize());
        assertNull(output.getRows());
        assertNull(output.getRow());
        assertNull(output.getUri());
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void rateLimitErrorIsActionableAndDoesNotExposeToken() {
        stubFor(get(urlPathEqualTo(PATH))
            .willReturn(aResponse().withStatus(429).withBody("rate limited")));
        var error = assertThrows(IllegalStateException.class,
            () -> task(FetchType.FETCH, false).run(runContextFactory.of()));

        assertTrue(error.getMessage().contains("rate limit"));
        assertFalse(error.getMessage().contains("test-token"));
    }

    @Test
    void emptyResponseBodyFailsClearly() {
        stubFor(get(urlPathEqualTo(PATH)).willReturn(aResponse().withStatus(200).withBody("")));
        var error = assertThrows(IllegalStateException.class,
            () -> task(FetchType.FETCH, false).run(runContextFactory.of()));

        assertTrue(error.getMessage().contains("empty response body"));
    }

    @Test
    void remoteHttpBaseUrlIsRejected() {
        var invalidUrlTask = ListIssues.builder()
            .token(Property.ofValue("test-token"))
            .baseUrl(Property.ofValue("http://api.example.com/rest"))
            .apiVersion(Property.ofValue("2024-10-15"))
            .orgId(Property.ofValue("org-id"))
            .severities(Property.ofValue(List.of()))
            .fetchType(Property.ofValue(FetchType.FETCH))
            .build();
        var error = assertThrows(IllegalArgumentException.class,
            () -> invalidUrlTask.run(runContextFactory.of()));

        assertTrue(error.getMessage().contains("HTTPS URL"));
    }

    @Test
    void onlyOfficialSnykHttpsHostsAreAccepted() {
        for (var host : List.of("api.snyk.io", "api.us.snyk.io", "api.eu.snyk.io", "api.au.snyk.io")) {
            assertDoesNotThrow(() -> SnykConnection.validateBaseUrl("https://" + host + "/rest"), host);
        }

        var nonSnyk = assertThrows(IllegalArgumentException.class,
            () -> SnykConnection.validateBaseUrl("https://api.snyk.io.attacker.example/rest"));
        assertTrue(nonSnyk.getMessage().contains("official Snyk API host"));

        var customPort = assertThrows(IllegalArgumentException.class,
            () -> SnykConnection.validateBaseUrl("https://api.snyk.io:8443/rest"));
        assertTrue(customPort.getMessage().contains("custom remote ports"));
    }

    @Test
    void repeatedPaginationLinkFailsInsteadOfLooping() {
        stubFor(get(urlPathEqualTo(PATH))
            .willReturn(okJson("""
                {"data":[{"id":"issue-1","type":"issue"}],"links":{"next":"http://localhost:18089/rest/orgs/org-id/issues?version=2024-10-15"}}
                """)));
        var error = assertThrows(IllegalStateException.class,
            () -> task(FetchType.FETCH, true).run(runContextFactory.of()));

        assertTrue(error.getMessage().contains("repeated pagination link"));
    }

    @ParameterizedTest(name = "rejects unsafe pagination link: {0}")
    @MethodSource("unsafePaginationLinks")
    void paginationLinkMustStayOnConfiguredIssuesEndpoint(String description, String nextHref) {
        stubFor(get(urlPathEqualTo(PATH))
            .willReturn(okJson("""
                {"data":[{"id":"issue-1","type":"issue"}],"links":{"next":{"href":"%s"}}}
                """.formatted(nextHref))));

        var error = assertThrows(IllegalStateException.class,
            () -> task(FetchType.FETCH, true).run(runContextFactory.of()));

        assertTrue(error.getMessage().contains("unsafe pagination link"), description);
        verify(1, getRequestedFor(urlPathEqualTo(PATH)));
    }

    static Stream<Arguments> unsafePaginationLinks() {
        return Stream.of(
            Arguments.of("foreign origin", "https://attacker.example/rest/orgs/org-id/issues?version=2024-10-15"),
            Arguments.of("scheme-relative authority", "//attacker.example/rest/orgs/org-id/issues?version=2024-10-15"),
            Arguments.of("different path on same host", "http://localhost:18089/rest/orgs/other-org/issues?version=2024-10-15"),
            Arguments.of("dot-segment traversal", "../orgs/other-org/issues?version=2024-10-15"),
            Arguments.of("encoded dot-segment traversal", "/%2e%2e/orgs/org-id/issues?version=2024-10-15"),
            Arguments.of("REST-prefix lookalike", "/restaurant/orgs/org-id/issues?version=2024-10-15")
        );
    }

    @Test
    void rootRelativePaginationWorksWhenBaseUrlHasNoRestPath() throws Exception {
        stubFor(get(urlPathEqualTo("/orgs/org-id/issues"))
            .inScenario("pagination-with-root-base")
            .whenScenarioStateIs(Scenario.STARTED)
            .willReturn(okJson("""
                {"data":[{"id":"root-page-1","type":"issue"}],
                 "links":{"next":{"href":"/orgs/org-id/issues?version=2024-10-15&starting_after=root-cursor"}}}
                """))
            .willSetStateTo("root-page-2"));
        stubFor(get(urlPathEqualTo("/orgs/org-id/issues"))
            .withQueryParam("starting_after", equalTo("root-cursor"))
            .inScenario("pagination-with-root-base")
            .whenScenarioStateIs("root-page-2")
            .willReturn(okJson("""
                {"data":[{"id":"root-page-2","type":"issue"}],"links":{}}
                """)));

        var output = task(FetchType.FETCH, false, "http://localhost:18089").run(runContextFactory.of());

        assertEquals(2L, output.getSize());
        assertEquals(2, output.getRows().size());
        verify(2, getRequestedFor(urlPathEqualTo("/orgs/org-id/issues")));
        verify(1, getRequestedFor(urlPathEqualTo("/orgs/org-id/issues"))
            .withQueryParam("starting_after", equalTo("root-cursor")));
    }

    @Test
    void malformedJsonFailsClearly() {
        stubFor(get(urlPathEqualTo(PATH)).willReturn(aResponse().withStatus(200).withBody("{not-json")));
        var error = assertThrows(IllegalStateException.class,
            () -> task(FetchType.FETCH, false).run(runContextFactory.of()));

        assertTrue(error.getMessage().contains("invalid JSON"));
    }


    private ListIssues task(FetchType fetchType, boolean highAndCritical) {
        return task(fetchType, highAndCritical, BASE_URL);
    }

    private ListIssues task(FetchType fetchType, boolean highAndCritical, String rBaseUrl) {
        return ListIssues.builder()
            .token(Property.ofValue("test-token"))
            .baseUrl(Property.ofValue(rBaseUrl))
            .apiVersion(Property.ofValue("2024-10-15"))
            .orgId(Property.ofValue("org-id"))
            .severities(highAndCritical
                ? Property.ofValue(List.of(SnykConnection.Severity.CRITICAL, SnykConnection.Severity.HIGH))
                : Property.ofValue(List.of()))
            .fetchType(Property.ofValue(fetchType))
            .build();
    }
}
