package io.kestra.plugin.snyk;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.kestra.core.exceptions.IllegalVariableEvaluationException;
import io.kestra.core.exceptions.ResourceExpiredException;
import io.kestra.core.http.client.configurations.HttpConfiguration;
import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.conditions.ConditionContext;
import io.kestra.core.models.executions.Execution;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.triggers.AbstractTrigger;
import io.kestra.core.models.triggers.PollingTriggerInterface;
import io.kestra.core.models.triggers.TriggerContext;
import io.kestra.core.models.triggers.TriggerOutput;
import io.kestra.core.models.triggers.TriggerService;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.JacksonMapper;
import io.kestra.core.storages.kv.KVMetadata;
import io.kestra.core.storages.kv.KVValue;
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
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(title = "Trigger on new Snyk issues", description = """
        Polls Snyk for issues and emits one execution for each newly detected issue.
        """)
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
    static final Duration STATE_TTL = Duration.ofDays(365);
    static final int MAX_IDS_PER_STATE_SHARD = 5_000;
    private static final int MAX_PENDING_ISSUES = 100;

    @Schema(
        title = "Polling interval",
        description = """
        How often Snyk is polled (default `PT15M`). The trigger emits one execution per evaluation, so a backlog drains at one issue per interval.
        """
    )
    @Builder.Default
    @PluginProperty(group = "execution")
    private final Duration interval = Duration.ofMinutes(15);

    @Schema(title = "Snyk API token", description = """
        API token used to authenticate with Snyk. Store it as a Kestra secret.
        """)
    @NotNull
    @PluginProperty(secret = true, group = "connection")
    @ToString.Exclude
    private Property<String> token;

    @Schema(title = "Snyk REST API base URL", description = """
        Official regional Snyk REST API base URL. The default is `https://api.snyk.io/rest`.
        """)
    @NotNull
    @Builder.Default
    @PluginProperty(group = "connection")
    private Property<String> baseUrl = Property.ofValue(SnykConnection.DEFAULT_BASE_URL);

    @Schema(title = "Snyk REST API version", description = """
        Snyk REST API version in YYYY-MM-DD format, optionally followed by a stability suffix. Defaults to `2024-10-15`.
        """)
    @NotNull
    @Builder.Default
    @PluginProperty(group = "connection")
    private Property<String> apiVersion = Property.ofValue(SnykConnection.DEFAULT_VERSION);

    @Schema(
        title = "Snyk organization ID",
        description = """
            Snyk organization whose issues the trigger monitors.
            """
    )
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> orgId;

    @Schema(
        title = "Optional severity filter",
        description = """
            Severities to monitor. If omitted, issues of all severity levels are monitored.
            """
    )
    @PluginProperty(group = "processing")
    private Property<List<SnykConnection.Severity>> severities;

    @Schema(title = "HTTP client options", description = """
        Optional HTTP settings such as timeouts, proxy, and TLS.
        """)
    @PluginProperty(group = "advanced")
    private HttpConfiguration options;

    @Override
    public Optional<Execution> evaluate(ConditionContext conditionContext, TriggerContext context) throws IllegalVariableEvaluationException {
        try {
            return evaluateInternal(conditionContext, context);
        } catch (IllegalVariableEvaluationException e) {
            throw e;
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to poll Snyk issues or persist trigger state: " + e.getMessage(), e);
        }
    }

    private Optional<Execution> evaluateInternal(ConditionContext conditionContext, TriggerContext context) throws Exception {
        var runContext = conditionContext.getRunContext();
        var rToken = runContext.render(token).as(String.class)
            .filter(value -> !value.isBlank())
            .orElseThrow(() -> new IllegalArgumentException("token is required and must not be blank."));
        var rBaseUrl = runContext.render(baseUrl).as(String.class).orElse(SnykConnection.DEFAULT_BASE_URL);
        var rVersion = runContext.render(apiVersion).as(String.class).orElse(SnykConnection.DEFAULT_VERSION);
        var rOrgId = runContext.render(orgId).as(String.class)
            .filter(value -> !value.isBlank())
            .orElseThrow(() -> new IllegalArgumentException("orgId is required and must not be blank."));
        var rSeverities = severities == null ? List.<SnykConnection.Severity>of()
            : runContext.render(severities).asList(SnykConnection.Severity.class);

        var key = stateKey(context);
        var rConfigurationKey = configurationKey(rOrgId, rBaseUrl, rVersion, rSeverities);
        var storedState = loadState(runContext, context.getNamespace(), key, rConfigurationKey);
        var previous = storedState != null && rConfigurationKey.equals(storedState.configurationKey()) ? storedState : null;
        if (previous != null && !previous.pending().isEmpty()) {
            var nextIssue = previous.pending().getFirst();
            var remaining = new ArrayList<Map<String, Object>>(previous.pending().subList(1, previous.pending().size()));
            var generated = execution(conditionContext, context, nextIssue);
            saveState(runContext, context.getNamespace(), key, rConfigurationKey, previous.knownIds(), remaining, previous);
            return Optional.of(generated);
        }

        var known = previous == null ? Set.<String>of() : new LinkedHashSet<>(previous.knownIds());
        var currentIds = new LinkedHashSet<String>();
        var newIssues = new ArrayList<Map<String, Object>>();
        SnykConnection.walkIssuePages(
            runContext, options, rToken, rBaseUrl, rVersion, rOrgId, rSeverities, true, false, page -> {
                for (Map<String, Object> issue : page) {
                    var id = issue.get("id");
                    if (id == null || id.toString().isBlank()) {
                        throw new IllegalStateException("Snyk API returned an issue without an id; trigger state was not advanced.");
                    }
                    var issueId = id.toString();
                    var firstOccurrence = currentIds.add(issueId);
                    if (firstOccurrence && previous != null && previous.initialized() && !known.contains(issueId)
                        && newIssues.size() < MAX_PENDING_ISSUES) {
                        newIssues.add(issue);
                    }
                }
            }
        );

        if (previous == null || !previous.initialized()) {
            saveState(runContext, context.getNamespace(), key, rConfigurationKey, List.copyOf(currentIds), List.of(), storedState);
            return Optional.empty();
        }

        var acceptedNewIds = new LinkedHashSet<String>();
        for (Map<String, Object> issue : newIssues) {
            acceptedNewIds.add(String.valueOf(issue.get("id")));
        }
        var idsToPersist = currentIds.stream()
            .filter(issueId -> known.contains(issueId) || acceptedNewIds.contains(issueId))
            .toList();

        if (newIssues.isEmpty()) {
            saveState(runContext, context.getNamespace(), key, rConfigurationKey, idsToPersist, List.of(), previous);
            return Optional.empty();
        }

        var first = newIssues.getFirst();
        var remaining = new ArrayList<>(newIssues.subList(1, newIssues.size()));
        var generated = execution(conditionContext, context, first);
        saveState(runContext, context.getNamespace(), key, rConfigurationKey, idsToPersist, remaining, previous);
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

    static String stateKey(TriggerContext context) {
        var identity = String.join("\n", context.getFlowId(), context.getTriggerId());
        return KV_PREFIX + UUID.nameUUIDFromBytes(identity.getBytes(StandardCharsets.UTF_8));
    }

    private static String configurationKey(
        String rOrgId,
        String rBaseUrl,
        String rVersion,
        List<SnykConnection.Severity> rSeverities
    ) {
        var severityKey = rSeverities == null ? "" : rSeverities.stream()
            .filter(Objects::nonNull)
            .map(Enum::name)
            .sorted()
            .collect(Collectors.joining(","));
        var normalizedBaseUrl = rBaseUrl == null ? "" : rBaseUrl.trim().replaceAll("/+$", "");
        var identity = String.join("\n", rOrgId, normalizedBaseUrl, rVersion, severityKey);
        return UUID.nameUUIDFromBytes(identity.getBytes(StandardCharsets.UTF_8)).toString();
    }

    private static State loadState(RunContext runContext, String namespace, String key, String rConfigurationKey) throws Exception {
        Optional<KVValue> stored;
        try {
            stored = runContext.namespaceKv(namespace).getValue(key);
        } catch (ResourceExpiredException e) {
            runContext.logger().warn("Snyk issue trigger state expired; pending issues and issues created while state was unavailable may be skipped. Establishing a new baseline.");
            return null;
        }
        if (stored.isEmpty() || stored.get().value() == null) {
            return null;
        }

        var raw = stored.get().value();
        var values = raw instanceof String json
            ? MAPPER.readValue(json, new TypeReference<Map<String, Object>>() {})
            : MAPPER.convertValue(raw, new TypeReference<Map<String, Object>>() {});
        var storedConfigurationKey = values.get("configurationKey");
        if (!(values.get("generation") instanceof String generation)) {
            runContext.logger().warn("Snyk issue trigger state has no shard generation; pending issues and issues created while state was unavailable may be skipped. Establishing a new baseline.");
            return null;
        }

        var shardCount = MAPPER.convertValue(values.getOrDefault("knownShardCount", 0), Integer.class);
        var shardsWrittenAt = values.get("shardsWrittenAt") instanceof Number timestamp ? timestamp.longValue() : 0L;
        if (shardCount == null || shardCount < 0) {
            runContext.logger().warn("Snyk issue trigger state has an invalid shard count; pending issues and issues created while state was unavailable may be skipped. Establishing a new baseline.");
            return null;
        }
        if (!rConfigurationKey.equals(storedConfigurationKey)) {
            if (storedConfigurationKey instanceof String previousConfigurationKey) {
                return new State(previousConfigurationKey, generation, shardCount, List.of(), List.of(),
                    Boolean.TRUE.equals(values.get("initialized")), shardsWrittenAt);
            }
            return null;
        }

        var ids = new ArrayList<String>();
        for (var index = 0; index < shardCount; index++) {
            var shardKey = stateShardKey(key, generation, index);
            Optional<KVValue> shard;
            try {
                shard = runContext.namespaceKv(namespace).getValue(shardKey);
            } catch (ResourceExpiredException e) {
                runContext.logger().warn("Snyk issue trigger state shard {} expired; pending issues and issues created while state was unavailable may be skipped. Establishing a new baseline.", shardKey);
                return new State(rConfigurationKey, generation, shardCount, List.of(), List.of(), false, shardsWrittenAt);
            }
            if (shard.isEmpty() || shard.get().value() == null) {
                runContext.logger().warn("Snyk issue trigger state shard {} is missing; pending issues and issues created while state was unavailable may be skipped. Establishing a new baseline.", shardKey);
                return new State(rConfigurationKey, generation, shardCount, List.of(), List.of(), false, shardsWrittenAt);
            }
            var shardRaw = shard.get().value();
            var shardIds = shardRaw instanceof String json
                ? MAPPER.readValue(json, new TypeReference<List<String>>() {})
                : MAPPER.convertValue(shardRaw, new TypeReference<List<String>>() {});
            ids.addAll(shardIds);
        }

        var pending = MAPPER.convertValue(values.getOrDefault("pending", List.of()),
            new TypeReference<List<Map<String, Object>>>() {});
        return new State(rConfigurationKey, generation, shardCount, List.copyOf(ids),
            pending == null ? List.of() : List.copyOf(pending), Boolean.TRUE.equals(values.get("initialized")), shardsWrittenAt);
    }

    private void saveState(
        RunContext runContext,
        String namespace,
        String key,
        String rConfigurationKey,
        List<String> knownIds,
        List<Map<String, Object>> pending,
        State previous
    ) throws Exception {
        var rKnownIds = List.copyOf(knownIds);
        var rPending = List.copyOf(pending);
        var sameIds = previous != null
            && previous.initialized()
            && rConfigurationKey.equals(previous.configurationKey())
            && new LinkedHashSet<>(previous.knownIds()).equals(new LinkedHashSet<>(rKnownIds));
        var now = Instant.now();
        var shouldRefreshShards = !sameIds
            || previous.shardsWrittenAt() == 0L
            || now.toEpochMilli() - previous.shardsWrittenAt() >= STATE_TTL.toMillis() / 2;
        var generation = sameIds ? previous.generation() : UUID.randomUUID().toString().replace("-", "");
        var shards = shouldRefreshShards ? chunkKnownIds(rKnownIds) : List.<List<String>>of();
        var shardCount = sameIds ? previous.knownShardCount() : shards.size();
        var shardsWrittenAt = shouldRefreshShards ? now.toEpochMilli() : previous.shardsWrittenAt();
        var metadata = Map.of(
            "configurationKey", rConfigurationKey,
            "generation", generation,
            "knownShardCount", shardCount,
            "shardsWrittenAt", shardsWrittenAt,
            "pending", rPending,
            "initialized", true
        );

        var kv = runContext.namespaceKv(namespace);
        var lastAttemptedShard = -1;
        try {
            if (!shards.isEmpty()) {
                for (var index = 0; index < shards.size(); index++) {
                    lastAttemptedShard = index;
                    kv.put(stateShardKey(key, generation, index),
                        new KVValueAndMetadata(new KVMetadata("Snyk issue trigger state shard", STATE_TTL),
                            MAPPER.writeValueAsString(shards.get(index))), true);
                }
            }
            kv.put(key, new KVValueAndMetadata(new KVMetadata("Snyk issue trigger state", STATE_TTL),
                MAPPER.writeValueAsString(metadata)), true);
        } catch (Exception writeFailure) {
            if (!sameIds) {
                for (var index = 0; index <= lastAttemptedShard; index++) {
                    var stagedShardKey = stateShardKey(key, generation, index);
                    try {
                        kv.delete(stagedShardKey);
                    } catch (Exception cleanupFailure) {
                        runContext.logger().warn("Failed to clean up staged Snyk state shard {} after a state write failure: {}",
                            stagedShardKey, cleanupFailure.getMessage());
                    }
                }
            }
            throw writeFailure;
        }

        if (!sameIds && previous != null && previous.generation() != null) {
            for (var index = 0; index < previous.knownShardCount(); index++) {
                var staleShardKey = stateShardKey(key, previous.generation(), index);
                try {
                    if (!kv.delete(staleShardKey)) {
                        runContext.logger().warn("Snyk issue trigger state was committed, but stale shard {} was not deleted.",
                            staleShardKey);
                    }
                } catch (Exception cleanupFailure) {
                    runContext.logger().warn("Snyk issue trigger state was committed, but stale shard cleanup failed for {}: {}",
                        staleShardKey, cleanupFailure.getMessage());
                }
            }
        }
    }

    static List<List<String>> chunkKnownIds(List<String> ids) {
        var chunks = new ArrayList<List<String>>();
        for (var offset = 0; offset < ids.size(); offset += MAX_IDS_PER_STATE_SHARD) {
            chunks.add(List.copyOf(ids.subList(offset, Math.min(offset + MAX_IDS_PER_STATE_SHARD, ids.size()))));
        }
        return List.copyOf(chunks);
    }

    private static String stateShardKey(String key, String generation, int index) {
        return key + "-g-" + generation + "-ids-" + index;
    }

    private record State(String configurationKey, String generation, int knownShardCount, List<String> knownIds, List<Map<String, Object>> pending, boolean initialized, long shardsWrittenAt) {}

    @Builder
    @Getter
    @Schema(title = "Snyk issue trigger output", description = """
        Issue details for the Snyk issue that caused this execution.
        """)
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(title = "Snyk issue ID", description = """
        Identifier of the issue that caused this execution.
        """)
        private final String issueId;

        @Schema(title = "Snyk issue", description = """
        Complete JSON:API issue object returned by Snyk.
        """)
        private final Map<String, Object> issue;
    }
}
