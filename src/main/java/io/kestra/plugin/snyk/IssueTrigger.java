package io.kestra.plugin.snyk;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.kestra.core.exceptions.IllegalVariableEvaluationException;
import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.conditions.ConditionContext;
import io.kestra.core.models.executions.Execution;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.triggers.AbstractTrigger;
import io.kestra.core.models.triggers.PollingTriggerInterface;
import io.kestra.core.models.triggers.TriggerContext;
import io.kestra.core.models.triggers.TriggerOutput;
import io.kestra.core.models.triggers.TriggerService;
import io.kestra.core.http.client.configurations.HttpConfiguration;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.JacksonMapper;
import io.kestra.core.storages.kv.KVMetadata;
import io.kestra.core.storages.kv.KVValueAndMetadata;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(title = "Trigger on new Snyk issues", description = "Polls Snyk for issues and emits one execution for each newly detected issue.")
@Plugin(
    examples = @Example(
        title = "Alert on new critical issues",
        full = true,
        code = """
            id: snyk_alert_on_new_issues
            namespace: company.security

            triggers:
              - id: new_critical_issue
                type: io.kestra.plugin.snyk.IssueTrigger
                token: "{{ secret('SNYK_API_TOKEN') }}"
                orgId: "{{ secret('SNYK_ORG_ID') }}"
                severities:
                  - CRITICAL
                interval: PT15M

            tasks:
              - id: log_issue
                type: io.kestra.plugin.core.log.Log
                message: "New Snyk issue: {{ trigger.issueId }}"
            """
    )
)
public class IssueTrigger extends AbstractTrigger implements PollingTriggerInterface, TriggerOutput<IssueTrigger.Output> {
    private static final ObjectMapper MAPPER = JacksonMapper.ofJson(false);
    private static final String KV_PREFIX = "snyk-issue-trigger-";

    @Schema(title = "Polling interval", description = "How often Snyk is polled for issues.")
    @lombok.Builder.Default
    private final Duration interval = Duration.ofMinutes(15);

    @Schema(title = "Snyk API token", description = "API token used to authenticate with Snyk. Store it as a Kestra secret.")
    @NotNull
    @PluginProperty(secret = true, group = "connection")
    @ToString.Exclude
    private Property<String> token;

    @Schema(title = "Snyk REST API base URL", description = "Regional Snyk REST API base URL.")
    @NotNull
    @lombok.Builder.Default
    @PluginProperty(group = "connection")
    private Property<String> baseUrl = Property.ofValue(SnykConnection.DEFAULT_BASE_URL);

    @Schema(title = "Snyk REST API version", description = "API version in YYYY-MM-DD format, optionally followed by a stability suffix.")
    @NotNull
    @lombok.Builder.Default
    @PluginProperty(group = "connection")
    private Property<String> apiVersion = Property.ofValue(SnykConnection.DEFAULT_VERSION);

    @Schema(title = "Snyk organization ID")
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> orgId;

    @Schema(title = "Optional severity filter")
    @PluginProperty(group = "processing")
    private Property<List<SnykConnection.Severity>> severities;

    @Schema(title = "HTTP client options", description = "Optional HTTP settings such as timeouts, proxy, and TLS.")
    @PluginProperty(group = "advanced")
    private HttpConfiguration options;

    @Override
    public Optional<Execution> evaluate(ConditionContext conditionContext, TriggerContext context) throws IllegalVariableEvaluationException {
        try {
            return evaluateInternal(conditionContext, context);
        } catch (IllegalVariableEvaluationException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to poll Snyk issues or persist trigger state.", e);
        }
    }

    private Optional<Execution> evaluateInternal(ConditionContext conditionContext, TriggerContext context) throws Exception {
        RunContext runContext = conditionContext.getRunContext();
        String renderedToken = runContext.render(token).as(String.class)
            .filter(value -> !value.isBlank())
            .orElseThrow(() -> new IllegalArgumentException("token is required and must not be blank."));
        String renderedBaseUrl = runContext.render(baseUrl).as(String.class).orElse(SnykConnection.DEFAULT_BASE_URL);
        String renderedVersion = runContext.render(apiVersion).as(String.class).orElse(SnykConnection.DEFAULT_VERSION);
        String renderedOrgId = runContext.render(orgId).as(String.class)
            .filter(value -> !value.isBlank())
            .orElseThrow(() -> new IllegalArgumentException("orgId is required and must not be blank."));
        List<SnykConnection.Severity> renderedSeverities = severities == null ? List.of()
            : runContext.render(severities).asList(SnykConnection.Severity.class);

        String key = stateKey(context);
        State previous = loadState(runContext, context.getNamespace(), key);
        if (previous != null && !previous.pending().isEmpty()) {
            Map<String, Object> nextIssue = previous.pending().getFirst();
            List<Map<String, Object>> remaining = new ArrayList<>(previous.pending().subList(1, previous.pending().size()));
            Execution generated = execution(conditionContext, context, nextIssue);
            saveState(runContext, context.getNamespace(), key, new State(previous.knownIds(), remaining, true));
            return Optional.of(generated);
        }

        Set<String> known = previous == null ? Set.of() : new LinkedHashSet<>(previous.knownIds());
        Set<String> currentIds = new LinkedHashSet<>();
        List<Map<String, Object>> newIssues = new ArrayList<>();
        SnykConnection.walkIssuePages(
            runContext, options, renderedToken, renderedBaseUrl, renderedVersion, renderedOrgId,
            renderedSeverities, true, false, page -> {
                for (Map<String, Object> issue : page) {
                    Object id = issue.get("id");
                    if (id == null || id.toString().isBlank()) {
                        throw new IllegalStateException("Snyk API returned an issue without an id; trigger state was not advanced.");
                    }
                    String issueId = id.toString();
                    currentIds.add(issueId);
                    if (previous != null && previous.initialized() && !known.contains(issueId)) {
                        newIssues.add(issue);
                    }
                }
            }
        );

        // The first successful poll establishes a baseline rather than alerting on every historical issue.
        if (previous == null || !previous.initialized()) {
            saveState(runContext, context.getNamespace(), key, new State(List.copyOf(currentIds), List.of(), true));
            return Optional.empty();
        }

        if (newIssues.isEmpty()) {
            saveState(runContext, context.getNamespace(), key, new State(List.copyOf(currentIds), List.of(), true));
            return Optional.empty();
        }

        Map<String, Object> first = newIssues.getFirst();
        List<Map<String, Object>> remaining = new ArrayList<>(newIssues.subList(1, newIssues.size()));
        Execution generated = execution(conditionContext, context, first);
        saveState(runContext, context.getNamespace(), key, new State(List.copyOf(currentIds), remaining, true));
        return Optional.of(generated);
    }

    private Execution execution(ConditionContext conditionContext, TriggerContext context, Map<String, Object> issue) {
        return TriggerService.generateExecution(
            this,
            conditionContext,
            context,
            Output.builder()
                .issueId(String.valueOf(issue.get("id")))
                .issue(issue)
                .build()
        );
    }

    private static String stateKey(TriggerContext context) {
        String identity = context.getFlowId() + "\n" + context.getTriggerId();
        return KV_PREFIX + UUID.nameUUIDFromBytes(identity.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static State loadState(RunContext runContext, String namespace, String key) throws Exception {
        var stored = runContext.namespaceKv(namespace).getValue(key);
        if (stored.isEmpty() || stored.get().value() == null) {
            return null;
        }
        Object raw = stored.get().value();
        Map<String, Object> values;
        if (raw instanceof String json) {
            values = MAPPER.readValue(json, new TypeReference<Map<String, Object>>() {});
        } else {
            values = MAPPER.convertValue(raw, new TypeReference<Map<String, Object>>() {});
        }
        List<String> ids = MAPPER.convertValue(values.getOrDefault("knownIds", List.of()), new TypeReference<List<String>>() {});
        List<Map<String, Object>> pending = MAPPER.convertValue(values.getOrDefault("pending", List.of()), new TypeReference<List<Map<String, Object>>>() {});
        return new State(ids, pending, Boolean.TRUE.equals(values.get("initialized")));
    }

    private static void saveState(RunContext runContext, String namespace, String key, State state) throws Exception {
        String value = MAPPER.writeValueAsString(Map.of(
            "knownIds", state.knownIds(),
            "pending", state.pending(),
            "initialized", state.initialized()
        ));
        runContext.namespaceKv(namespace).put(
            key,
            new KVValueAndMetadata(new KVMetadata("Snyk issue trigger state", (Duration) null), value),
            true
        );
    }

    private record State(List<String> knownIds, List<Map<String, Object>> pending, boolean initialized) {}

    @lombok.Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "Snyk issue ID", description = "Identifier of the issue that caused this execution.")
        private final String issueId;

        @Schema(title = "Snyk issue", description = "Complete JSON:API issue object returned by Snyk.")
        private final Map<String, Object> issue;
    }
}
