package io.kestra.plugin.snyk;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import io.kestra.core.http.HttpRequest;
import io.kestra.core.http.HttpResponse;
import io.kestra.core.http.client.HttpClient;
import io.kestra.core.http.client.HttpClientResponseException;
import io.kestra.core.http.client.configurations.HttpConfiguration;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.Task;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.JacksonMapper;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Shared Snyk connection properties and REST API handling. */
@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class SnykConnection extends Task {
    public static final String DEFAULT_BASE_URL = "https://api.snyk.io/rest";
    public static final String DEFAULT_VERSION = "2024-10-15";
    private static final com.fasterxml.jackson.databind.ObjectMapper MAPPER = JacksonMapper.ofJson(false);
    private static final int MAX_PAGES = 10_000;

    @Schema(title = "Snyk API token", description = "API token used to authenticate with Snyk. Store it as a Kestra secret.")
    @NotNull
    @PluginProperty(secret = true, group = "connection")
    @ToString.Exclude
    protected Property<String> token;

    @Schema(title = "Snyk REST API base URL", description = "Regional Snyk REST API base URL. Defaults to https://api.snyk.io/rest.")
    @NotNull
    @lombok.Builder.Default
    @PluginProperty(group = "connection")
    protected Property<String> baseUrl = Property.ofValue(DEFAULT_BASE_URL);

    @Schema(title = "Snyk REST API version", description = "API version in YYYY-MM-DD format, optionally followed by a stability suffix.")
    @NotNull
    @lombok.Builder.Default
    @PluginProperty(group = "connection")
    protected Property<String> apiVersion = Property.ofValue(DEFAULT_VERSION);

    @Schema(title = "HTTP client options", description = "Optional HTTP settings such as timeouts, proxy, and TLS.")
    @PluginProperty(group = "advanced")
    protected HttpConfiguration options;

    public enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW
    }

    public static List<Map<String, Object>> fetchIssues(
        RunContext runContext,
        HttpConfiguration options,
        String token,
        String baseUrl,
        String version,
        String orgId,
        List<Severity> severities,
        boolean paginate,
        boolean stopAfterFirst
    ) throws Exception {
        List<Map<String, Object>> result = new ArrayList<>();
        walkIssuePages(runContext, options, token, baseUrl, version, orgId, severities, paginate, stopAfterFirst, result::addAll);
        return result;
    }

    @FunctionalInterface
    public interface IssuePageConsumer {
        void accept(List<Map<String, Object>> page) throws Exception;
    }

    /** Walks the API cursor without retaining every page in memory; consumers may stream each page to storage. */
    public static long walkIssuePages(
        RunContext runContext,
        HttpConfiguration options,
        String token,
        String baseUrl,
        String version,
        String orgId,
        List<Severity> severities,
        boolean paginate,
        boolean stopAfterFirst,
        IssuePageConsumer consumer
    ) throws Exception {
        requireNonBlank(token, "token");
        requireNonBlank(orgId, "orgId");
        requireNonBlank(version, "version");
        URI base = validateBaseUrl(baseUrl);
        String orgPath = "orgs/" + encodePathSegment(orgId) + "/issues";
        String endpointPath = base.getRawPath().replaceAll("/+$", "") + "/" + orgPath;
        StringBuilder firstUrl = new StringBuilder(base.toString().replaceAll("/+$", "")).append("/").append(orgPath)
            .append("?version=").append(encode(version));
        if (severities != null && !severities.isEmpty()) {
            String joined = severities.stream().filter(java.util.Objects::nonNull)
                .map(s -> s.name().toLowerCase(Locale.ROOT)).distinct().reduce((a, b) -> a + "," + b).orElse("");
            if (!joined.isBlank()) {
                firstUrl.append("&effective_severity_level=").append(encode(joined));
            }
        }

        Set<String> visited = new HashSet<>();
        URI current = URI.create(firstUrl.toString());
        HttpConfiguration configuration = options == null ? HttpConfiguration.builder().build() : options;
        long total = 0L;

        try (HttpClient client = new HttpClient(runContext, configuration)) {
            int pages = 0;
            while (current != null) {
                if (++pages > MAX_PAGES) {
                    throw new IllegalStateException("Snyk pagination exceeded " + MAX_PAGES + " pages; refusing to continue.");
                }
                String canonical = current.normalize().toString();
                if (!visited.add(canonical)) {
                    throw new IllegalStateException("Snyk API returned a repeated pagination link; refusing to loop indefinitely.");
                }

                HttpRequest request = HttpRequest.builder()
                    .uri(current)
                    .method("GET")
                    .addHeader("Authorization", "token " + token)
                    .addHeader("Accept", "application/vnd.api+json")
                    .addHeader("Content-Type", "application/vnd.api+json")
                    .build();

                HttpResponse<String> response;
                try {
                    response = client.request(request, String.class);
                } catch (HttpClientResponseException e) {
                    int status = e.getResponse() != null && e.getResponse().getStatus() != null
                        ? e.getResponse().getStatus().getCode() : -1;
                    String reason = switch (status) {
                        case 401, 403 -> "Authentication/authorization failed. Verify the Snyk API token and organization access.";
                        case 404 -> "Organization or endpoint was not found. Verify orgId and baseUrl.";
                        case 429 -> "Snyk rate limit was exceeded. Retry after the rate-limit window.";
                        default -> "Snyk API request failed.";
                    };
                    throw new IllegalStateException(reason + " HTTP status: " + status + ".", e);
                }

                String body = response.getBody();
                if (body == null || body.isBlank()) {
                    throw new IllegalStateException("Snyk API returned an empty response body.");
                }
                JsonNode root;
                try {
                    root = MAPPER.readTree(body);
                } catch (IOException e) {
                    throw new IllegalStateException("Snyk API returned invalid JSON.", e);
                }
                JsonNode data = root.get("data");
                if (data == null || !data.isArray()) {
                    throw new IllegalStateException("Snyk API response is missing the expected JSON:API 'data' array.");
                }

                List<Map<String, Object>> pageIssues = new ArrayList<>();
                for (JsonNode issue : data) {
                    Map<String, Object> row = MAPPER.convertValue(issue, new TypeReference<LinkedHashMap<String, Object>>() {});
                    pageIssues.add(row);
                    if (stopAfterFirst) {
                        consumer.accept(List.of(row));
                        return total + 1;
                    }
                }
                if (!pageIssues.isEmpty()) {
                    consumer.accept(pageIssues);
                    total += pageIssues.size();
                }
                if (!paginate) {
                    break;
                }
                current = nextPage(root, current, base, endpointPath);
            }
        }
        return total;
    }

    private static URI nextPage(JsonNode root, URI current, URI base, String endpointPath) {
        JsonNode next = root.path("links").path("next");
        if (next.isMissingNode() || next.isNull()) {
            return null;
        }
        String value;
        if (next.isTextual()) {
            value = next.asText();
        } else if (next.isObject() && next.path("href").isTextual()) {
            value = next.path("href").asText();
        } else {
            throw new IllegalStateException("Snyk API returned an unsupported pagination link format.");
        }
        if (value.isBlank()) {
            return null;
        }
        URI candidate = current.resolve(value);
        if (candidate.getUserInfo() != null || candidate.getFragment() != null
            || !sameOrigin(base, candidate) || !candidate.getRawPath().equals(endpointPath)) {
            throw new IllegalStateException("Snyk API returned an unsafe pagination link outside the configured issues endpoint.");
        }
        return candidate;
    }

    private static URI validateBaseUrl(String raw) {
        requireNonBlank(raw, "baseUrl");
        URI uri;
        try {
            uri = URI.create(raw.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("baseUrl must be a valid absolute HTTP(S) URL.", e);
        }
        String scheme = uri.getScheme();
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
            || !("https".equalsIgnoreCase(scheme)
                || ("http".equalsIgnoreCase(scheme) && isLoopback(uri.getHost())))) {
            throw new IllegalArgumentException("baseUrl must be an HTTPS URL (HTTP is allowed only for localhost WireMock tests) without credentials, query, or fragment.");
        }
        return uri;
    }

    private static boolean isLoopback(String host) {
        return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host) || "[::1]".equals(host);
    }

    private static boolean sameOrigin(URI left, URI right) {
        return left.getScheme().equalsIgnoreCase(right.getScheme())
            && left.getHost().equalsIgnoreCase(right.getHost())
            && effectivePort(left) == effectivePort(right);
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static String encodePathSegment(String value) {
        return encode(value).replace("+", "%20");
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static void requireNonBlank(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required and must not be blank.");
        }
    }
}
