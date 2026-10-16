package io.kestra.plugin.snyk;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.conditions.ConditionContext;
import io.kestra.core.models.flows.Flow;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.triggers.TriggerContext;
import io.kestra.core.runners.DefaultRunContext;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.runners.RunContextInitializer;
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
class IssueTriggerTest {
    private static final String BASE_URL = "http://localhost:18089/rest";
    private static final String PATH = "/rest/orgs/org-id/issues";

    @Inject
    RunContextFactory runContextFactory;

    @Inject
    RunContextInitializer runContextInitializer;

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

    @Test
    @Timeout(value = 35, unit = TimeUnit.SECONDS)
    void triggerStateIsIsolatedByOrganizationAndSeverityConfiguration() throws Exception {
        String flowId = "snyk-config-flow-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String triggerId = "snyk-config-trigger-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
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

        stubFor(get(urlPathEqualTo(PATH)).willReturn(okJson("""
            {"data":[{"id":"baseline","type":"issue"}],"links":{}}
            """)));
        var baselineTrigger = configuredTrigger(triggerId, "org-id", List.of());
        var baselineRunContext = runContextInitializer.forScheduler(
            (DefaultRunContext) runContextFactory.of(flow, baselineTrigger), triggerContext, baselineTrigger
        );
        var baselineCondition = ConditionContext.builder().runContext(baselineRunContext).flow(flow).build();
        assertTrue(baselineTrigger.evaluate(baselineCondition, triggerContext).isEmpty());

        stubFor(get(urlPathEqualTo(PATH))
            .withQueryParam("effective_severity_level", equalTo("critical"))
            .willReturn(okJson("""
                {"data":[{"id":"historical-critical","type":"issue"}],"links":{}}
                """)));
        var criticalTrigger = configuredTrigger(triggerId, "org-id", List.of(SnykConnection.Severity.CRITICAL));
        var criticalRunContext = runContextInitializer.forScheduler(
            (DefaultRunContext) runContextFactory.of(flow, criticalTrigger), triggerContext, criticalTrigger
        );
        var criticalCondition = ConditionContext.builder().runContext(criticalRunContext).flow(flow).build();
        assertTrue(criticalTrigger.evaluate(criticalCondition, triggerContext).isEmpty(),
            "changing severity filter must establish a new baseline rather than emit historical matching issues");

        stubFor(get(urlPathEqualTo("/rest/orgs/other-org/issues")).willReturn(okJson("""
            {"data":[{"id":"historical-other-org","type":"issue"}],"links":{}}
            """)));
        var otherOrgTrigger = configuredTrigger(triggerId, "other-org", List.of());
        var otherOrgRunContext = runContextInitializer.forScheduler(
            (DefaultRunContext) runContextFactory.of(flow, otherOrgTrigger), triggerContext, otherOrgTrigger
        );
        var otherOrgCondition = ConditionContext.builder().runContext(otherOrgRunContext).flow(flow).build();
        assertTrue(otherOrgTrigger.evaluate(otherOrgCondition, triggerContext).isEmpty(),
            "changing organization must establish a new baseline rather than emit historical issues");
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void pendingOverflowIsQueuedInBatchesAndPickedUpByLaterPolls() throws Exception {
        String flowId = "snyk-backlog-flow-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String triggerId = "snyk-backlog-trigger-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
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

        String issues = java.util.stream.IntStream.range(0, 101)
            .mapToObj(i -> "{\"id\":\"new-" + i + "\",\"type\":\"issue\"}")
            .collect(java.util.stream.Collectors.joining(","));
        stubFor(get(urlPathEqualTo(PATH))
            .inScenario("snyk-large-backlog")
            .whenScenarioStateIs(com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED)
            .willReturn(okJson("""
                {"data":[{"id":"existing","type":"issue"}],"links":{}}
                """))
            .willSetStateTo("large-backlog"));
        stubFor(get(urlPathEqualTo(PATH))
            .inScenario("snyk-large-backlog")
            .whenScenarioStateIs("large-backlog")
            .willReturn(okJson("{\"data\":[" + issues + "],\"links\":{}}")));

        var trigger = configuredTrigger(triggerId, "org-id", List.of());
        var runContext = runContextInitializer.forScheduler(
            (DefaultRunContext) runContextFactory.of(flow, trigger), triggerContext, trigger
        );
        var conditionContext = ConditionContext.builder().runContext(runContext).flow(flow).build();
        assertTrue(trigger.evaluate(conditionContext, triggerContext).isEmpty(), "initial poll establishes the baseline");

        var first = trigger.evaluate(conditionContext, triggerContext);
        assertTrue(first.isPresent());
        assertEquals("new-0", ((Map<?, ?>) first.get().getTrigger().getVariables()).get("issueId"));

        // The first 100 issues are emitted individually. The 101st ID is not marked known,
        // so a later scan discovers it after the pending queue drains.
        for (int expected = 1; expected < 100; expected++) {
            var next = trigger.evaluate(conditionContext, triggerContext);
            assertTrue(next.isPresent(), "queued issue new-" + expected + " should be emitted");
            assertEquals("new-" + expected, ((Map<?, ?>) next.get().getTrigger().getVariables()).get("issueId"));
        }
        var overflow = trigger.evaluate(conditionContext, triggerContext);
        assertTrue(overflow.isPresent(), "overflow issue should be picked up by a later scan rather than deadlocking polling");
        assertEquals("new-100", ((Map<?, ?>) overflow.get().getTrigger().getVariables()).get("issueId"));
        verify(3, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    void knownIssueIdsAreSplitIntoBoundedKvShards() throws Exception {
        var ids = java.util.stream.IntStream.range(0, IssueTrigger.MAX_IDS_PER_STATE_SHARD + 1)
            .mapToObj(i -> "issue-" + i)
            .toList();
        var shards = IssueTrigger.chunkKnownIds(ids);
        assertEquals(2, shards.size());
        assertEquals(IssueTrigger.MAX_IDS_PER_STATE_SHARD, shards.getFirst().size());
        assertEquals(1, shards.getLast().size());
        assertEquals(ids, shards.stream().flatMap(List::stream).toList());
    }

    @Test
    void stateMetadataTtlIsOneYearAndIndependentOfPollingInterval() {
        assertEquals(Duration.ofDays(365), IssueTrigger.STATE_TTL);
    }

    @Test
    @Timeout(value = 35, unit = TimeUnit.SECONDS)
    void missingShardRecoversByEstablishingANewBaseline() throws Exception {
        String flowId = "snyk-missing-shard-flow-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String triggerId = "snyk-missing-shard-trigger-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        var flow = Flow.builder().id(flowId).namespace("company.security").tenantId("test-tenant").build();
        var triggerContext = TriggerContext.builder().tenantId("test-tenant").namespace(flow.getNamespace())
            .flowId(flowId).triggerId(triggerId).date(ZonedDateTime.now(ZoneOffset.UTC)).build();

        stubFor(get(urlPathEqualTo(PATH))
            .inScenario("missing-shard-recovery")
            .whenScenarioStateIs(com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED)
            .willReturn(okJson("""
                {"data":[{"id":"existing","type":"issue"}],"links":{}}
                """))
            .willSetStateTo("state-corrupted"));
        stubFor(get(urlPathEqualTo(PATH))
            .inScenario("missing-shard-recovery")
            .whenScenarioStateIs("state-corrupted")
            .willReturn(okJson("""
                {"data":[{"id":"existing","type":"issue"},{"id":"new-during-recovery","type":"issue"}],"links":{}}
                """)));

        var trigger = configuredTrigger(triggerId, "org-id", List.of());
        var runContext = runContextInitializer.forScheduler((DefaultRunContext) runContextFactory.of(flow, trigger), triggerContext, trigger);
        var conditionContext = ConditionContext.builder().runContext(runContext).flow(flow).build();
        assertTrue(trigger.evaluate(conditionContext, triggerContext).isEmpty());

        var stateKey = IssueTrigger.stateKey(triggerContext);
        var kv = runContext.namespaceKv(flow.getNamespace());
        var shard = kv.list().stream().filter(entry -> entry.key().startsWith(stateKey + "-g-"))
            .findFirst().orElseThrow(() -> new AssertionError("baseline should have created an ID shard"));
        assertTrue(kv.delete(shard.key()), "test setup should delete the selected shard");

        assertTrue(trigger.evaluate(conditionContext, triggerContext).isEmpty(),
            "a missing shard should recover via a new baseline rather than fail every poll");
        assertTrue(trigger.evaluate(conditionContext, triggerContext).isEmpty(),
            "the recovered baseline should suppress historical duplicates");
        verify(3, getRequestedFor(urlPathEqualTo(PATH)));
    }

    @Test
    @Timeout(value = 35, unit = TimeUnit.SECONDS)
    void drainPollDoesNotRewriteKnownIdShards() throws Exception {
        String flowId = "snyk-drain-flow-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String triggerId = "snyk-drain-trigger-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        var flow = Flow.builder().id(flowId).namespace("company.security").tenantId("test-tenant").build();
        var triggerContext = TriggerContext.builder().tenantId("test-tenant").namespace(flow.getNamespace())
            .flowId(flowId).triggerId(triggerId).date(ZonedDateTime.now(ZoneOffset.UTC)).build();

        stubFor(get(urlPathEqualTo(PATH))
            .inScenario("drain-shard-reuse")
            .whenScenarioStateIs(com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED)
            .willReturn(okJson("""
                {"data":[{"id":"existing","type":"issue"}],"links":{}}
                """))
            .willSetStateTo("new-issues"));
        stubFor(get(urlPathEqualTo(PATH))
            .inScenario("drain-shard-reuse")
            .whenScenarioStateIs("new-issues")
            .willReturn(okJson("""
                {"data":[{"id":"existing","type":"issue"},{"id":"new-1","type":"issue"},{"id":"new-2","type":"issue"}],"links":{}}
                """)));

        var trigger = configuredTrigger(triggerId, "org-id", List.of());
        var runContext = runContextInitializer.forScheduler((DefaultRunContext) runContextFactory.of(flow, trigger), triggerContext, trigger);
        var conditionContext = ConditionContext.builder().runContext(runContext).flow(flow).build();
        assertTrue(trigger.evaluate(conditionContext, triggerContext).isEmpty());

        var emitted = trigger.evaluate(conditionContext, triggerContext);
        assertTrue(emitted.isPresent());
        assertEquals("new-1", ((Map<?, ?>) emitted.get().getTrigger().getVariables()).get("issueId"));

        var stateKey = IssueTrigger.stateKey(triggerContext);
        var kv = runContext.namespaceKv(flow.getNamespace());
        var before = kv.list().stream().filter(entry -> entry.key().startsWith(stateKey + "-g-"))
            .map(entry -> entry.key() + "|" + entry.updateDate()).sorted().toList();
        assertFalse(before.isEmpty(), "expected an ID shard after detecting new issues");

        var queued = trigger.evaluate(conditionContext, triggerContext);
        assertTrue(queued.isPresent());
        assertEquals("new-2", ((Map<?, ?>) queued.get().getTrigger().getVariables()).get("issueId"));

        var after = kv.list().stream().filter(entry -> entry.key().startsWith(stateKey + "-g-"))
            .map(entry -> entry.key() + "|" + entry.updateDate()).sorted().toList();
        assertEquals(before, after, "draining a pending issue should update only the state pointer, not the ID shards");
        verify(2, getRequestedFor(urlPathEqualTo(PATH)));
    }

    private IssueTrigger configuredTrigger(String triggerId, String orgId, List<SnykConnection.Severity> severities) {
        return IssueTrigger.builder()
            .id(triggerId)
            .type(IssueTrigger.class.getName())
            .token(Property.ofValue("test-token"))
            .baseUrl(Property.ofValue(BASE_URL))
            .apiVersion(Property.ofValue("2024-10-15"))
            .orgId(Property.ofValue(orgId))
            .severities(Property.ofValue(severities))
            .interval(Duration.ofMinutes(15))
            .build();
    }
}
