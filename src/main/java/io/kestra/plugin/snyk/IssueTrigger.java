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
import io.kestra.core.http.client.configurations.HttpConfiguration;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.triggers.TriggerService;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.JacksonMapper;
import io.kestra.core.storages.kv.KVMetadata;
import io.kestra.core.storages.kv.KVValueAndMetadata;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
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
    private static final int MAX_TRACKED_ISSUE_IDS = 20_000;
    private static final int MAX_PENDING_ISSUES = 100;
    private static final int MAX_STATE_SIZE_BYTES = 900 * 1024;

    @Schema(
        title = "Polling interval",
        description = "How often Snyk is polled. The trigger emits one execution per evaluation, so a backlog drains at one issue per interval."
    )
    @Builder.Default
    private final Duration interval = Duration.ofMinutes(15);

    @Schema(title = "Snyk API token", description = "API token used to authenticate with Snyk. Store it as a Kestra secret.")
    @NotNull
    @PluginProperty(secret = true, group = "connection")
    @ToString.Exclude
    private Property<String> token;

    @Schema(title = "Snyk REST API base URL", description = "Regional Snyk REST API base URL.")
    @NotNull
    @Builder.Default
    @PluginProperty(group = "connection")
    private Property<String> baseUrl = Property.ofValue(SnykConnection.DEFAULT_BASE_URL);

    @Schema(title = "Snyk REST API version", description = "API version in YYYY-MM-DD format, optionally followed by a stability suffix.")
    @NotNull
    @Builder.Default
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
        var runContext = conditionContext.getRunContext();
        var renderedToken = runContext.render(token).as(String.class)
            .filter(value -> !value.isBlank())
            .orElseThrow(() -> new IllegalArgumentException("token is required and must not be blank."));
        var renderedBaseUrl = runContext.render(baseUrl).as(String.class).orElse(SnykConnection.DEFAULT_BASE_URL);
        var renderedVersion = runContext.render(apiVersion).as(String.class).orElse(SnykConnection.DEFAULT_VERSION);
        var renderedOrgId = runContext.render(orgId).as(String.class)
            .filter(value -> !value.isBlank())
            .orElseThrow(() -> new IllegalArgumentException("orgId is required and must not be blank."));
        var renderedSeverities = severities == null ? List.<SnykConnection.Severity>of()
            : runContext.render(severities).asList(SnykConnection.Severity.class);

        var key = stateKey(context, renderedOrgId, renderedBaseUrl, renderedVersion, renderedSeverities);
        var previous = loadState(runContext, context.getNamespace(), key);
        if (previous != null && !previous.pending().isEmpty()) {
            var nextIssue = previous.pending().getFirst();
            var remaining = new ArrayList<Map<String, Object>>(previous.pending().subList(1, previous.pending().size()));
            var generated = execution(conditionContext, context, nextIssue);
            saveState(runContext, context.getNamespace(), key, new State(previous.knownIds(), remaining, true));
            return Optional.of(generated);
        }

        var known = previous == null ? Set.<String>of() : new LinkedHashSet<>(previous.knownIds());
        var currentIds = new LinkedHashSet<String>();
        var newIssues = new ArrayList<Map<String, Object>>();
        SnykConnection.walkIssuePages(
            runContext, options, renderedToken, renderedBaseUrl, renderedVersion, renderedOrgId,
            renderedSeverities, true, false, page -> {
                for (Map<String, Object> issue : page) {
                    var id = issue.get("id");
                    if (id == null || id.toString().isBlank()) {
                        throw new IllegalStateException("Snyk API returned an issue without an id; trigger state was not advanced.");
                    }
                    var issueId = id.toString();
                    // Cursor pagination can overlap when the underlying issue collection changes between pages.
                    // Only enqueue an ID once per snapshot, even if it appears on multiple pages.
                    var firstOccurrence = currentIds.add(issueId);
                    if (currentIds.size() > MAX_TRACKED_ISSUE_IDS) {
                        throw new IllegalStateException(
                            "Snyk IssueTrigger found more than " + MAX_TRACKED_ISSUE_IDS + " issues for this filter. " +
                                "Trigger state was not advanced; narrow the severity filter or use ListIssues for full exports."
                        );
                    }
                    if (firstOccurrence && previous != null && previous.initialized() && !known.contains(issueId)) {
                        newIssues.add(issue);
                        if (newIssues.size() > MAX_PENDING_ISSUES) {
                            throw new IllegalStateException(
                                "Snyk IssueTrigger detected more than " + MAX_PENDING_ISSUES + " new issues in one poll. " +
                                    "Trigger state was not advanced to avoid dropping issues or writing an oversized queue; " +
                                    "narrow the severity filter and retry. Pending issues are emitted one per polling interval."
                            );
                        }
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

        var first = newIssues.getFirst();
        var remaining = new ArrayList<>(newIssues.subList(1, newIssues.size()));
        var generated = execution(conditionContext, context, first);
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

    private static String stateKey(
        TriggerContext context,
        String orgId,
        String baseUrl,
        String apiVersion,
        List<SnykConnection.Severity> severities
    ) {
        var severityKey = severities == null ? "" : severities.stream()
            .filter(Objects::nonNull)
            .map(Enum::name)
            .sorted()
            .collect(Collectors.joining(","));
        var normalizedBaseUrl = baseUrl == null ? "" : baseUrl.trim().replaceAll("/+$", "");
        var identity = String.join("\n",
            context.getFlowId(),
            context.getTriggerId(),
            orgId,
            normalizedBaseUrl,
            apiVersion,
            severityKey
        );
        return KV_PREFIX + UUID.nameUUIDFromBytes(identity.getBytes(StandardCharsets.UTF_8));
    }

    private static State loadState(RunContext runContext, String namespace, String key) throws Exception {
        var stored = runContext.namespaceKv(namespace).getValue(key);
        if (stored.isEmpty() || stored.get().value() == null) {
            return null;
        }
        var raw = stored.get().value();
        Map<String, Object> values;
        if (raw instanceof String json) {
            values = MAPPER.readValue(json, new TypeReference<Map<String, Object>>() {});
        } else {
            values = MAPPER.convertValue(raw, new TypeReference<Map<String, Object>>() {});
        }
        var ids = MAPPER.convertValue(values.getOrDefault("knownIds", List.of()), new TypeReference<List<String>>() {});
        var pending = MAPPER.convertValue(values.getOrDefault("pending", List.of()), new TypeReference<List<Map<String, Object>>>() {});
        return new State(ids, pending, Boolean.TRUE.equals(values.get("initialized")));
    }

    private static void saveState(RunContext runContext, String namespace, String key, State state) throws Exception {
        if (state.knownIds().size() > MAX_TRACKED_ISSUE_IDS) {
            throw new IllegalStateException("Snyk IssueTrigger state exceeds the limit of " + MAX_TRACKED_ISSUE_IDS + " tracked issue IDs.");
        }
        if (state.pending().size() > MAX_PENDING_ISSUES) {
            throw new IllegalStateException("Snyk IssueTrigger pending queue exceeds the limit of " + MAX_PENDING_ISSUES + " issues.");
        }
        var value = MAPPER.writeValueAsString(Map.of(
            "knownIds", state.knownIds(),
            "pending", state.pending(),
            "initialized", state.initialized()
        ));
        if (value.getBytes(StandardCharsets.UTF_8).length > MAX_STATE_SIZE_BYTES) {
            throw new IllegalStateException(
                "Snyk IssueTrigger state exceeds the safe namespace key-value payload size of " + MAX_STATE_SIZE_BYTES +
                    " bytes. Narrow the severity filter; trigger state was not advanced."
            );
        }
        runContext.namespaceKv(namespace).put(
            key,
            new KVValueAndMetadata(new KVMetadata("Snyk issue trigger state", (Duration) null), value),
            true
        );
    }

    private record State(List<String> knownIds, List<Map<String, Object>> pending, boolean initialized) {}

    @Builder
    @Getter
    @Schema(title = "Snyk issue trigger output", description = "Issue details for the Snyk issue that caused this execution.")
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "Snyk issue ID", description = "Identifier of the issue that caused this execution.")
        private final String issueId;

        @Schema(title = "Snyk issue", description = "Complete JSON:API issue object returned by Snyk.")
        private final Map<String, Object> issue;
    }
}
