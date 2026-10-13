package io.kestra.plugin.snyk;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.common.FetchType;
import io.kestra.core.runners.RunContextFactory;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.*;

@KestraTest
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
            .withHeader("Authorization", equalTo("token test-token"))
            .withHeader("Accept", equalTo("application/vnd.api+json"))
            .willReturn(okJson("""
                {
                  "data": [{"id":"issue-1","type":"issue","attributes":{"effective_severity_level":"critical"}}],
                  "links": {"next":"http://localhost:18089/rest/orgs/org-id/issues?version=2024-10-15&starting_after=cursor-1"}
                }
                """)));

        stubFor(get(urlPathEqualTo(PATH))
            .withQueryParam("starting_after", equalTo("cursor-1"))
            .willReturn(okJson("""
                {"data":[{"id":"issue-2","type":"issue","attributes":{"effective_severity_level":"high"}}],"links":{}}
                """)));

        ListIssues task = task(FetchType.FETCH, true);
        var output = task.run(runContextFactory.of());

        assertEquals(2L, output.getSize());
        assertEquals(2, output.getRows().size());
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
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
    void storeWritesRowsAndReturnsCount() throws Exception {
        stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson("""
            {"data":[{"id":"issue-1","type":"issue"},{"id":"issue-2","type":"issue"}],"links":{}}
            """)));

        var output = task(FetchType.STORE, false).run(runContextFactory.of());

        assertEquals(2L, output.getSize());
        assertNotNull(output.getUri());
        assertNull(output.getRows());
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

        IllegalStateException error = assertThrows(IllegalStateException.class,
            () -> task(FetchType.FETCH, false).run(runContextFactory.of()));

        assertTrue(error.getMessage().contains("Authentication/authorization failed"));
        assertFalse(error.getMessage().contains("test-token"));
    }

    @Test
    void repeatedPaginationLinkFailsInsteadOfLooping() {
        stubFor(get(urlPathEqualTo(PATH))
            .willReturn(okJson("""
                {"data":[{"id":"issue-1","type":"issue"}],"links":{"next":"http://localhost:18089/rest/orgs/org-id/issues?version=2024-10-15"}}
                """)));

        IllegalStateException error = assertThrows(IllegalStateException.class,
            () -> task(FetchType.FETCH, true).run(runContextFactory.of()));

        assertTrue(error.getMessage().contains("repeated pagination link"));
    }

    @Test
    void paginationLinkCannotEscapeConfiguredOrigin() {
        stubFor(get(urlPathEqualTo(PATH))
            .willReturn(okJson("""
                {"data":[],"links":{"next":"https://attacker.example/rest/orgs/org-id/issues?version=2024-10-15"}}
                """)));

        IllegalStateException error = assertThrows(IllegalStateException.class,
            () -> task(FetchType.FETCH, true).run(runContextFactory.of()));

        assertTrue(error.getMessage().contains("unsafe pagination link"));
    }

    @Test
    void malformedJsonFailsClearly() {
        stubFor(get(urlPathEqualTo(PATH)).willReturn(aResponse().withStatus(200).withBody("{not-json")));

        IllegalStateException error = assertThrows(IllegalStateException.class,
            () -> task(FetchType.FETCH, false).run(runContextFactory.of()));

        assertTrue(error.getMessage().contains("invalid JSON"));
    }

    private ListIssues task(FetchType fetchType, boolean highAndCritical) {
        return ListIssues.builder()
            .token(Property.ofValue("test-token"))
            .baseUrl(Property.ofValue(BASE_URL))
            .apiVersion(Property.ofValue("2024-10-15"))
            .orgId(Property.ofValue("org-id"))
            .severities(highAndCritical
                ? Property.ofValue(java.util.List.of(SnykConnection.Severity.CRITICAL, SnykConnection.Severity.HIGH))
                : Property.ofValue(java.util.List.of()))
            .fetchType(Property.ofValue(fetchType))
            .build();
    }
}
