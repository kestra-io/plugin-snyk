package io.kestra.plugin.snyk;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.conditions.ConditionContext;
import io.kestra.core.models.flows.Flow;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.common.FetchType;
import io.kestra.core.models.triggers.TriggerContext;
import io.kestra.core.runners.DefaultRunContext;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.runners.RunContextInitializer;
import io.kestra.core.serializers.FileSerde;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.*;

@KestraTest(startWorker = false)
@WireMockTest(httpPort = 18089)
class ListIssuesTest {
    private static final String BASE_URL = "http://localhost:18089/rest";
    private static final String PATH = "/rest/orgs/org-id/issues";

    @Inject
    RunContextFactory runContextFactory;

    @Inject
    RunContextInitializer runContextInitializer;

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
                  "links": {"next":{"href":"http://localhost:18089/rest/orgs/org-id/issues?version=2024-10-15&starting_after=cursor-1"}}
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
            assertEquals("issue-1", ((Map<?, ?>) rows.get(0)).get("id"));
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

        IllegalStateException error = assertThrows(IllegalStateException.class,
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

        IllegalStateException error = assertThrows(IllegalStateException.class,
            () -> task(FetchType.FETCH, false).run(runContextFactory.of()));

        assertTrue(error.getMessage().contains("rate limit"));
        assertFalse(error.getMessage().contains("test-token"));
    }

    @Test
    void emptyResponseBodyFailsClearly() {
        stubFor(get(urlPathEqualTo(PATH)).willReturn(aResponse().withStatus(200).withBody("")));

        IllegalStateException error = assertThrows(IllegalStateException.class,
            () -> task(FetchType.FETCH, false).run(runContextFactory.of()));

        assertTrue(error.getMessage().contains("empty response body"));
    }

    @Test
    void remoteHttpBaseUrlIsRejected() {
        ListIssues invalidUrlTask = ListIssues.builder()
            .token(Property.ofValue("test-token"))
            .baseUrl(Property.ofValue("http://api.example.com/rest"))
            .apiVersion(Property.ofValue("2024-10-15"))
            .orgId(Property.ofValue("org-id"))
            .severities(Property.ofValue(List.of()))
            .fetchType(Property.ofValue(FetchType.FETCH))
            .build();

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
            () -> invalidUrlTask.run(runContextFactory.of()));

        assertTrue(error.getMessage().contains("HTTPS URL"));
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

    @Test
    @Timeout(value = 35, unit = TimeUnit.SECONDS)
    void establishesBaselineThenEmitsEachNewIssueOnce() throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
            .inScenario("snyk-issue-snapshots")
            .whenScenarioStateIs(com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED)
            .willReturn(okJson("""
                {"data":[{"id":"existing","type":"issue"}],"links":{}}
                """))
            .willSetStateTo("new-issues"));

        stubFor(get(urlPathEqualTo(PATH))
            .inScenario("snyk-issue-snapshots")
            .whenScenarioStateIs("new-issues")
            .willReturn(okJson("""
                {"data":[{"id":"existing","type":"issue"},{"id":"new-1","type":"issue"}],
                 "links":{"next":"http://localhost:18089/rest/orgs/org-id/issues?version=2024-10-15&starting_after=cursor-trigger"}}
                """))
            .willSetStateTo("new-issues-page2"));

        stubFor(get(urlPathEqualTo(PATH))
            .withQueryParam("starting_after", equalTo("cursor-trigger"))
            .inScenario("snyk-issue-snapshots")
            .whenScenarioStateIs("new-issues-page2")
            .willReturn(okJson("""
                {"data":[{"id":"new-1","type":"issue"},{"id":"new-2","type":"issue"}],"links":{}}
                """))
            .willSetStateTo("stable"));

        stubFor(get(urlPathEqualTo(PATH))
            .inScenario("snyk-issue-snapshots")
            .whenScenarioStateIs("stable")
            .willReturn(okJson("""
                {"data":[{"id":"existing","type":"issue"},{"id":"new-1","type":"issue"},{"id":"new-2","type":"issue"}],"links":{}}
                """)));

        String flowId = "snyk-flow-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String triggerId = "new-issues-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        IssueTrigger trigger = IssueTrigger.builder()
            .id(triggerId)
            .type(IssueTrigger.class.getName())
            .token(Property.ofValue("test-token"))
            .baseUrl(Property.ofValue(BASE_URL))
            .apiVersion(Property.ofValue("2024-10-15"))
            .orgId(Property.ofValue("org-id"))
            .severities(Property.ofValue(List.of()))
            .interval(java.time.Duration.ofMinutes(15))
            .build();
        var flow = Flow.builder()
            .id(flowId)
            .namespace("company.security")
            .tenantId("test-tenant")
            .build();
        var triggerContext = TriggerContext.builder()
            .tenantId("test-tenant")
            .namespace(flow.getNamespace())
            .flowId(flowId)
            .triggerId(triggerId)
            .date(ZonedDateTime.now(ZoneOffset.UTC))
            .build();
        var baseRunContext = (DefaultRunContext) runContextFactory.of(flow, trigger);
        var runContext = runContextInitializer.forScheduler(baseRunContext, triggerContext, trigger);
        var conditionContext = ConditionContext.builder()
            .runContext(runContext)
            .flow(flow)
            .build();

        assertTrue(trigger.evaluate(conditionContext, triggerContext).isEmpty(),
            "first poll should baseline existing issues");

        var first = trigger.evaluate(conditionContext, triggerContext);
        assertTrue(first.isPresent(), "first newly detected issue should trigger");
        assertEquals("new-1", ((Map<?, ?>) first.get().getTrigger().getVariables()).get("issueId"));

        var second = trigger.evaluate(conditionContext, triggerContext);
        assertTrue(second.isPresent(), "queued issue should trigger on the next poll");
        assertEquals("new-2", ((Map<?, ?>) second.get().getTrigger().getVariables()).get("issueId"));

        assertTrue(trigger.evaluate(conditionContext, triggerContext).isEmpty(),
            "unchanged snapshot should not trigger duplicates");
        verify(4, getRequestedFor(urlPathEqualTo(PATH)));
    }

    private ListIssues task(FetchType fetchType, boolean highAndCritical) {
        return ListIssues.builder()
            .token(Property.ofValue("test-token"))
            .baseUrl(Property.ofValue(BASE_URL))
            .apiVersion(Property.ofValue("2024-10-15"))
            .orgId(Property.ofValue("org-id"))
            .severities(highAndCritical
                ? Property.ofValue(java.util.List.of(SnykConnection.Severity.CRITICAL, SnykConnection.Severity.HIGH))
                : Property.ofValue(List.of()))
            .fetchType(Property.ofValue(fetchType))
            .build();
    }
}
