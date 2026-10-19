package io.kestra.plugin.snyk;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.models.tasks.common.FetchOutput;
import io.kestra.core.models.tasks.common.FetchType;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.FileSerde;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;
import reactor.core.publisher.Flux;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(title = "List Snyk issues", description = """
        Lists security issues for a Snyk organization using the Snyk REST API.
        """)
@Plugin(
    examples = {
        @Example(
            title = "Store critical and high-severity issues",
            full = true,
            code = """
                id: snyk_list_issues
                namespace: company.security

                tasks:
                  - id: list_issues
                    type: io.kestra.plugin.snyk.ListIssues
                    token: "{{ secret('SNYK_API_TOKEN') }}"
                    orgId: "{{ secret('SNYK_ORG_ID') }}"
                    severities:
                      - CRITICAL
                      - HIGH
                    fetchType: STORE
                """
        ),
        @Example(
            title = "Fetch issues in the EU region",
            full = true,
            code = """
                id: snyk_list_issues_eu
                namespace: company.security

                tasks:
                  - id: list_issues
                    type: io.kestra.plugin.snyk.ListIssues
                    token: "{{ secret('SNYK_API_TOKEN') }}"
                    orgId: "{{ secret('SNYK_ORG_ID') }}"
                    baseUrl: https://api.eu.snyk.io/rest
                    fetchType: FETCH
                """
        )
    }
)
public class ListIssues extends SnykConnection implements RunnableTask<FetchOutput> {
    @Schema(title = "Snyk organization ID", description = """
        The Snyk organization whose issues should be retrieved.
        """)
    @NotNull
    @PluginProperty(group = "main")
    private Property<String> orgId;

    @Schema(title = "Severity levels", description = """
        Optional severity filter. If omitted, issues of every severity are returned.
        """)
    @PluginProperty(group = "processing")
    private Property<List<Severity>> severities;

    @Schema(title = "Fetch mode", description = """
        FETCH returns all rows, FETCH_ONE returns the first row, STORE writes all rows to internal storage, and NONE returns only the count. Defaults to FETCH.
        """)
    @NotNull
    @Builder.Default
    @PluginProperty(group = "processing")
    private Property<FetchType> fetchType = Property.ofValue(FetchType.FETCH);

    @Override
    public FetchOutput run(RunContext runContext) throws Exception {
        var rToken = runContext.render(token).as(String.class)
            .filter(value -> !value.isBlank())
            .orElseThrow(() -> new IllegalArgumentException("token is required and must not be blank."));
        var rBaseUrl = runContext.render(baseUrl).as(String.class).orElse(DEFAULT_BASE_URL);
        var rVersion = runContext.render(apiVersion).as(String.class).orElse(DEFAULT_VERSION);
        var rOrgId = runContext.render(orgId).as(String.class)
            .filter(value -> !value.isBlank())
            .orElseThrow(() -> new IllegalArgumentException("orgId is required and must not be blank."));
        var rSeverities = severities == null ? List.<Severity>of()
            : runContext.render(severities).asList(Severity.class);
        var mode = runContext.render(fetchType).as(FetchType.class).orElse(FetchType.FETCH);

        return switch (mode) {
            case FETCH_ONE -> {
                var issues = SnykConnection.fetchIssues(
                    runContext, options, rToken, rBaseUrl, rVersion, rOrgId,
                    rSeverities, false, true
                );
                yield FetchOutput.builder()
                    .row(issues.isEmpty() ? null : issues.getFirst())
                    .size(issues.isEmpty() ? 0L : 1L)
                    .build();
            }
            case FETCH -> {
                var issues = SnykConnection.fetchIssues(
                    runContext, options, rToken, rBaseUrl, rVersion, rOrgId,
                    rSeverities, true, false
                );
                yield FetchOutput.builder()
                    .rows(new ArrayList<>(issues))
                    .size((long) issues.size())
                    .build();
            }
            case STORE -> store(runContext, rToken, rBaseUrl, rVersion, rOrgId, rSeverities);
            case NONE -> FetchOutput.builder().size(SnykConnection.walkIssuePages(
                runContext, options, rToken, rBaseUrl, rVersion, rOrgId,
                rSeverities, true, false, page -> {}
            )).build();
        };
    }

    private FetchOutput store(
        RunContext runContext,
        String rToken,
        String rBaseUrl,
        String rVersion,
        String rOrgId,
        List<Severity> rSeverities
    ) throws Exception {
        var tempFile = runContext.workingDir().createTempFile(".ion").toFile();
        long count;
        try (var output = new BufferedOutputStream(new FileOutputStream(tempFile), FileSerde.BUFFER_SIZE)) {
            count = SnykConnection.walkIssuePages(
                runContext, options, rToken, rBaseUrl, rVersion, rOrgId,
                rSeverities, true, false, page -> FileSerde.writeAll(output, Flux.fromIterable(page)).block()
            );
        }
        var uri = runContext.storage().putFile(tempFile);
        return FetchOutput.builder().uri(uri).size(count).build();
    }
}
