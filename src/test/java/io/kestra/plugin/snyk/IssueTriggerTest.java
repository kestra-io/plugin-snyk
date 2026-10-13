package io.kestra.plugin.snyk;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
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

import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.*;

@KestraTest
@WireMockTest
class IssueTriggerTest {
    private static final String PATH = "/rest/orgs/org-id/issues";

    @Inject
    RunContextFactory runContextFactory;

    @Inject
    RunContextInitializer runContextInitializer;

    @Test
    void establishesBaselineThenEmitsEachNewIssueOnce(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(get(urlPathEqualTo(PATH))
            .inScenario("issue-snapshots")
            .whenScenarioStateIs(Scenario.STARTED)
            .willReturn(okJson("""
                {"data":[{"id":"existing","type":"issue"}],"links":{}}
                """))
            .willSetStateTo("new-issues"));

        stubFor(get(urlPathEqualTo(PATH))
            .inScenario("issue-snapshots")
            .whenScenarioStateIs("new-issues")
            .willReturn(okJson("""
                {"data":[{"id":"existing","type":"issue"},{"id":"new-1","type":"issue"},{"id":"new-2","type":"issue"}],"links":{}}
                """))
            .willSetStateTo("stable"));

        stubFor(get(urlPathEqualTo(PATH))
            .inScenario("issue-snapshots")
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
            .baseUrl(Property.ofValue(wireMockRuntimeInfo.getHttpBaseUrl() + "/rest"))
            .apiVersion(Property.ofValue("2024-10-15"))
            .orgId(Property.ofValue("org-id"))
            .severities(Property.ofValue(List.of()))
            .interval(Duration.ofMinutes(15))
            .build();
        Flow flow = Flow.builder()
            .id(flowId)
            .namespace("company.security")
            .tenantId("test-tenant")
            .build();
        TriggerContext triggerContext = TriggerContext.builder()
            .tenantId("test-tenant")
            .namespace(flow.getNamespace())
            .flowId(flowId)
            .triggerId(triggerId)
            .date(ZonedDateTime.now(ZoneOffset.UTC))
            .build();
        var baseRunContext = (DefaultRunContext) runContextFactory.of(flow, trigger);
        var runContext = runContextInitializer.forScheduler(baseRunContext, triggerContext, trigger);
        ConditionContext conditionContext = ConditionContext.builder()
            .runContext(runContext)
            .flow(flow)
            .build();

        assertTrue(trigger.evaluate(conditionContext, triggerContext).isEmpty(), "first poll should baseline existing issues");
        assertTrue(trigger.evaluate(conditionContext, triggerContext).isPresent(), "first newly detected issue should trigger");
        assertTrue(trigger.evaluate(conditionContext, triggerContext).isPresent(), "queued issue should trigger on the next poll");
        assertTrue(trigger.evaluate(conditionContext, triggerContext).isEmpty(), "unchanged snapshot should not trigger duplicates");
        verify(3, getRequestedFor(urlPathEqualTo(PATH)));
    }
}
