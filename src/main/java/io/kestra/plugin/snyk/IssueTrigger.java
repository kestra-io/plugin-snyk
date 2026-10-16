package io.kestra.plugin.snyk;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.kestra.core.exceptions.IllegalVariableEvaluationException;
import io.kestra.core.exceptions.ResourceExpiredException;
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
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
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
    // Each stored value remains bounded; the full baseline is split over expiring KV shards.
    static final int MAX_IDS_PER_STATE_SHARD = 5_000;
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
                    // Cursor pages may overlap while Snyk's underlying issue collection changes.
                    var firstOccurrence = currentIds.add(issueId);
                    if (firstOccurrence && previous != null && previous.initialized() && !known.contains(issueId)
                        && newIssues.size() < MAX_PENDING_ISSUES) {
                        newIssues.add(issue);
                    }
                }
            }
        );

        // The first successful scan after state expiry/configuration change establishes a clean baseline.
        if (previous == null || !previous.initialized()) {
            saveState(runContext, context.getNamespace(), key, new State(List.copyOf(currentIds), List.of(), true));
            return Optional.empty();
        }

        // Keep existing known IDs and IDs actually accepted into the queue. Overflow IDs remain unknown,
        // so a later scan can rediscover them after the bounded queue drains.
        var acceptedNewIds = new LinkedHashSet<String>();
        for (Map<String, Object> issue : newIssues) {
            acceptedNewIds.add(String.valueOf(issue.get("id")));
        }
        var idsToPersist = currentIds.stream()
            .filter(issueId -> known.contains(issueId) || acceptedNewIds.contains(issueId))
            .toList();

        if (newIssues.isEmpty()) {
            saveState(runContext, context.getNamespace(), key, new State(idsToPersist, List.of(), true));
            return Optional.empty();
        }

        var first = newIssues.getFirst();
        var remaining = new ArrayList<>(newIssues.subList(1, newIssues.size()));
        // Generate before saving state; if generation fails, this snapshot remains eligible for retry.
        var generated = execution(conditionContext, context, first);
        saveState(runContext, context.getNamespace(), key, new State(idsToPersist, remaining, true));
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
        Optional<KVValue> stored;
        try {
            stored = runContext.namespaceKv(namespace).getValue(key);
        } catch (ResourceExpiredException e) {
            return null;
        }
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

        var ids = new ArrayList<String>();
        if (values.get("generation") instanceof String generation) {
            var shardCount = MAPPER.convertValue(values.getOrDefault("knownShardCount", 0), Integer.class);
            if (shardCount < 0 || shardCount > 1_000_000) {
                throw new IllegalStateException("Snyk issue trigger state has an invalid ID-shard count; refusing to advance state.");
            }
            for (var index = 0; index < shardCount; index++) {
                Optional<KVValue> shard;
                try {
                    shard = runContext.namespaceKv(namespace).getValue(stateShardKey(key, generation, index));
                } catch (ResourceExpiredException e) {
                    throw new IllegalStateException(
                        "Snyk issue trigger ID shard expired before its state pointer; refusing to advance an incomplete snapshot.", e
                    );
                }
                if (shard.isEmpty() || shard.get().value() == null) {
                    throw new IllegalStateException(
                        "Snyk issue trigger state is missing an ID shard; refusing to treat the snapshot as a new baseline."
                    );
                }
                var shardRaw = shard.get().value();
                List<String> shardIds;
                if (shardRaw instanceof String json) {
                    shardIds = MAPPER.readValue(json, new TypeReference<List<String>>() {});
                } else {
                    shardIds = MAPPER.convertValue(shardRaw, new TypeReference<List<String>>() {});
                }
                ids.addAll(shardIds);
            }
        } else if (values.containsKey("knownIds")) {
            // Migrate the earlier inline-ID state format on the next successful save.
            ids.addAll(MAPPER.convertValue(values.getOrDefault("knownIds", List.of()), new TypeReference<List<String>>() {}));
        } else {
            throw new IllegalStateException("Snyk issue trigger state is missing both inline IDs and shard metadata; refusing to advance state.");
        }

        var pending = MAPPER.convertValue(values.getOrDefault("pending", List.of()), new TypeReference<List<Map<String, Object>>>() {});
        return new State(List.copyOf(ids), pending, Boolean.TRUE.equals(values.get("initialized")));
    }

    private void saveState(RunContext runContext, String namespace, String key, State state) throws Exception {
        var generation = UUID.randomUUID().toString().replace("-", "");
        var knownIds = new ArrayList<>(state.knownIds());
        var pending = new ArrayList<>(state.pending());
        var shards = chunkKnownIds(knownIds);
        var metadata = stateMetadata(generation, shards.size(), pending, state.initialized());

        // If issue objects make the pending payload too large, drop only its tail and unmark those IDs.
        // A later API scan can therefore rediscover every deferred issue without a permanent cap failure.
        while ((pending.size() > MAX_PENDING_ISSUES
            || MAPPER.writeValueAsBytes(metadata).length > MAX_STATE_SIZE_BYTES) && !pending.isEmpty()) {
            var dropped = pending.remove(pending.size() - 1);
            var droppedId = dropped.get("id");
            if (droppedId != null) {
                knownIds.removeIf(id -> id.equals(droppedId.toString()));
            }
            shards = chunkKnownIds(knownIds);
            metadata = stateMetadata(generation, shards.size(), pending, state.initialized());
        }
        if (MAPPER.writeValueAsBytes(metadata).length > MAX_STATE_SIZE_BYTES) {
            throw new IllegalStateException("Snyk issue trigger metadata exceeds the safe per-key size limit even with an empty pending queue.");
        }

        var kv = runContext.namespaceKv(namespace);
        var pointerTtl = stateTtl(interval);
        var shardTtl = stateShardTtl(interval);
        // Stage all shards before moving the metadata pointer. Incomplete writes leave the prior generation readable.
        for (var index = 0; index < shards.size(); index++) {
            var shardValue = MAPPER.writeValueAsString(shards.get(index));
            if (shardValue.getBytes(StandardCharsets.UTF_8).length > MAX_STATE_SIZE_BYTES) {
                throw new IllegalStateException("Snyk issue trigger ID shard exceeds the safe per-key size limit.");
            }
            kv.put(
                stateShardKey(key, generation, index),
                new KVValueAndMetadata(new KVMetadata("Snyk issue trigger state shard", shardTtl), shardValue),
                true
            );
        }

        var metadataValue = MAPPER.writeValueAsString(metadata);
        kv.put(
            key,
            new KVValueAndMetadata(new KVMetadata("Snyk issue trigger state", pointerTtl), metadataValue),
            true
        );
    }

    private static Map<String, Object> stateMetadata(
        String generation,
        int shardCount,
        List<Map<String, Object>> pending,
        boolean initialized
    ) {
        return Map.of(
            "generation", generation,
            "knownShardCount", shardCount,
            "pending", pending,
            "initialized", initialized
        );
    }

    private static String stateShardKey(String key, String generation, int index) {
        return key + "-g-" + generation + "-ids-" + index;
    }

    static List<List<String>> chunkKnownIds(List<String> ids) throws Exception {
        var chunks = new ArrayList<List<String>>();
        var current = new ArrayList<String>();
        int encodedArraySize = 2; // '[' and ']'; Jackson uses no whitespace for arrays.
        for (String id : ids) {
            if (id == null) {
                throw new IllegalStateException("Snyk issue trigger cannot persist a null issue ID.");
            }
            var encodedIdSize = MAPPER.writeValueAsBytes(id).length;
            var additionSize = (current.isEmpty() ? 0 : 1) + encodedIdSize;
            if (!current.isEmpty() && (current.size() >= MAX_IDS_PER_STATE_SHARD
                || encodedArraySize + additionSize > MAX_STATE_SIZE_BYTES)) {
                chunks.add(List.copyOf(current));
                current = new ArrayList<>();
                encodedArraySize = 2;
                additionSize = encodedIdSize;
            }
            if (encodedArraySize + additionSize > MAX_STATE_SIZE_BYTES) {
                throw new IllegalStateException("A Snyk issue ID is larger than the safe namespace KV value size.");
            }
            current.add(id);
            encodedArraySize += additionSize;
        }
        if (!current.isEmpty()) {
            chunks.add(List.copyOf(current));
        }
        // Final serialized-size assertion guards the estimate against mapper/configuration changes.
        for (var chunk : chunks) {
            if (MAPPER.writeValueAsBytes(chunk).length > MAX_STATE_SIZE_BYTES) {
                throw new IllegalStateException("Snyk issue trigger ID shard exceeds the safe per-key size limit.");
            }
        }
        return List.copyOf(chunks);
    }

    static Duration stateTtl(Duration interval) {
        if (interval == null || interval.isZero() || interval.isNegative()) {
            return Duration.ofHours(1);
        }
        try {
            return interval.multipliedBy(4);
        } catch (ArithmeticException e) {
            return Duration.ofDays(36_500);
        }
    }

    static Duration stateShardTtl(Duration interval) {
        var ttl = stateTtl(interval);
        if (interval == null || interval.isZero() || interval.isNegative()) {
            return ttl.plusMinutes(1);
        }
        try {
            return ttl.plus(interval);
        } catch (ArithmeticException e) {
            return Duration.ofDays(73_000);
        }
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
