package io.kestra.plugin.snyk;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import lombok.Builder;
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
import java.util.Objects;
import java.util.Set;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class SnykConnection extends Task {
    public static final String DEFAULT_BASE_URL = "https://api.snyk.io/rest";
    public static final String DEFAULT_VERSION = "2024-10-15";
    private static final ObjectMapper MAPPER = JacksonMapper.ofJson(false);
    private static final int MAX_PAGES = 10_000;
    private static final int ISSUES_PAGE_LIMIT = 100;
    private static final Set<String> SNYK_API_HOSTS = Set.of(
        "api.snyk.io",
        "api.us.snyk.io",
        "api.eu.snyk.io",
        "api.au.snyk.io"
    );

    @Schema(title = "Snyk API token", description = """
        API token used to authenticate with Snyk. Store it as a Kestra secret.
        """)
    @NotNull
    @PluginProperty(secret = true, group = "connection")
    @ToString.Exclude
    protected Property<String> token;

    @Schema(title = "Snyk REST API base URL", description = """
        Official regional Snyk REST API base URL (api.snyk.io, api.us.snyk.io, api.eu.snyk.io, or api.au.snyk.io). Defaults to https://api.snyk.io/rest.
        """)
    @NotNull
    @Builder.Default
    @PluginProperty(group = "connection")
    protected Property<String> baseUrl = Property.ofValue(DEFAULT_BASE_URL);

    @Schema(title = "Snyk REST API version", description = """
        API version in YYYY-MM-DD format, optionally followed by a stability suffix. Defaults to `2024-10-15`.
        """)
    @NotNull
    @Builder.Default
    @PluginProperty(group = "connection")
    protected Property<String> apiVersion = Property.ofValue(DEFAULT_VERSION);

    @Schema(title = "HTTP client options", description = """
        Optional HTTP settings such as timeouts, proxy, and TLS.
        """)
    @PluginProperty(group = "advanced")
    protected HttpConfiguration options;

    public enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW
    }

    public static List<Map<String, Object>> fetchIssues(
        RunContext runContext,
        HttpConfiguration options,
        String rToken,
        String rBaseUrl,
        String rVersion,
        String rOrgId,
        List<Severity> rSeverities,
        boolean paginate,
        boolean stopAfterFirst
    ) throws Exception {
        var result = new ArrayList<Map<String, Object>>();
        walkIssuePages(runContext, options, rToken, rBaseUrl, rVersion, rOrgId, rSeverities, paginate, stopAfterFirst, result::addAll);
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
        String rToken,
        String rBaseUrl,
        String rVersion,
        String rOrgId,
        List<Severity> rSeverities,
        boolean paginate,
        boolean stopAfterFirst,
        IssuePageConsumer consumer
    ) throws Exception {
        requireNonBlank(rToken, "token");
        requireNonBlank(rOrgId, "orgId");
        requireNonBlank(rVersion, "version");
        var base = validateBaseUrl(rBaseUrl);
        var orgPath = "orgs/" + encodePathSegment(rOrgId) + "/issues";
        var endpointPath = base.getRawPath().replaceAll("/+$", "") + "/" + orgPath;
        var firstUrl = new StringBuilder(base.toString().replaceAll("/+$", "")).append("/").append(orgPath)
            .append("?version=").append(encode(rVersion))
            .append("&limit=").append(ISSUES_PAGE_LIMIT);
        if (rSeverities != null && !rSeverities.isEmpty()) {
            var joined = rSeverities.stream().filter(Objects::nonNull)
                .map(s -> s.name().toLowerCase(Locale.ROOT)).distinct().reduce((a, b) -> a + "," + b).orElse("");
            if (!joined.isBlank()) {
                firstUrl.append("&effective_severity_level=").append(encode(joined));
            }
        }

        var visited = new HashSet<String>();
        var current = URI.create(firstUrl.toString());
        var configuration = options == null ? HttpConfiguration.builder().build() : options;
        var total = 0L;

        try (var client = new HttpClient(runContext, configuration)) {
            var pages = 0;
            while (current != null) {
                if (++pages > MAX_PAGES) {
                    throw new IllegalStateException("Snyk pagination exceeded " + MAX_PAGES + " pages; refusing to continue.");
                }
                var canonical = current.normalize().toString();
                if (!visited.add(canonical)) {
                    throw new IllegalStateException("Snyk API returned a repeated pagination link; refusing to loop indefinitely.");
                }

                var request = HttpRequest.builder()
                    .uri(current)
                    .method("GET")
                    .addHeader("Authorization", "token " + rToken)
                    .addHeader("Accept", "application/vnd.api+json")
                    .addHeader("Content-Type", "application/vnd.api+json")
                    .build();

                var response = requestPage(client, request);

                var body = response.getBody();
                if (body == null || body.isBlank()) {
                    throw new IllegalStateException("Snyk API returned an empty response body.");
                }
                var root = parseJsonBody(body);
                var data = root.get("data");
                if (data == null || !data.isArray()) {
                    throw new IllegalStateException("Snyk API response is missing the expected JSON:API 'data' array.");
                }

                var pageIssues = new ArrayList<Map<String, Object>>();
                for (JsonNode issue : data) {
                    var row = MAPPER.convertValue(issue, new TypeReference<LinkedHashMap<String, Object>>() {});
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

    private static HttpResponse<String> requestPage(HttpClient client, HttpRequest request) throws Exception {
        try {
            return client.request(request, String.class);
        } catch (HttpClientResponseException e) {
            var status = e.getResponse() != null && e.getResponse().getStatus() != null
                ? e.getResponse().getStatus().getCode() : -1;
            var reason = switch (status) {
                case 401, 403 -> "Authentication/authorization failed. Verify the Snyk API token and organization access.";
                case 404 -> "Organization or endpoint was not found. Verify orgId and baseUrl.";
                case 429 -> "Snyk rate limit was exceeded. Retry after the rate-limit window.";
                default -> "Snyk API request failed.";
            };
            throw new IllegalStateException(reason + " HTTP status: " + status + ".", e);
        }
    }

    private static JsonNode parseJsonBody(String body) {
        try {
            return MAPPER.readTree(body);
        } catch (IOException e) {
            throw new IllegalStateException("Snyk API returned invalid JSON.", e);
        }
    }

    private static URI nextPage(JsonNode root, URI current, URI base, String endpointPath) {
        var next = root.path("links").path("next");
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
        var candidate = resolveNextPage(value, current, base);
        if (candidate.getUserInfo() != null || candidate.getFragment() != null
            || !sameOrigin(base, candidate) || !Objects.equals(candidate.getRawPath(), endpointPath)) {
            throw new IllegalStateException("Snyk API returned an unsafe pagination link outside the configured issues endpoint.");
        }
        return candidate;
    }

    private static URI resolveNextPage(String value, URI current, URI base) {
        var link = URI.create(value);
        var linkPath = link.getRawPath();
        if (link.isAbsolute() || link.getRawAuthority() != null || linkPath == null || linkPath.isEmpty()) {
            return current.resolve(value);
        }

        var basePath = base.getRawPath().replaceAll("/+$", "");
        if (linkPath.equals(basePath) || linkPath.startsWith(basePath + "/")) {
            return current.resolve(value);
        }

        var rebasedPath = linkPath.startsWith("/") ? basePath + linkPath : basePath + "/" + linkPath;
        var rebased = new StringBuilder()
            .append(base.getScheme()).append("://").append(base.getRawAuthority()).append(rebasedPath);
        if (link.getRawQuery() != null) {
            rebased.append("?").append(link.getRawQuery());
        }
        if (link.getRawFragment() != null) {
            rebased.append("#").append(link.getRawFragment());
        }
        return URI.create(rebased.toString());
    }

    static URI validateBaseUrl(String rBaseUrl) {
        requireNonBlank(rBaseUrl, "baseUrl");
        URI uri;
        try {
            uri = URI.create(rBaseUrl.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("baseUrl must be a valid absolute HTTP(S) URL.", e);
        }
        var scheme = uri.getScheme();
        var host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        var officialSnykHttpsUrl = "https".equalsIgnoreCase(scheme)
            && SNYK_API_HOSTS.contains(host)
            && (uri.getPort() == -1 || uri.getPort() == 443);
        var loopbackHttpUrl = "http".equalsIgnoreCase(scheme) && isLoopback(host);
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
            || !(officialSnykHttpsUrl || loopbackHttpUrl)) {
            throw new IllegalArgumentException(
                "baseUrl must be an HTTPS URL using an official Snyk API host (api.snyk.io, api.us.snyk.io, api.eu.snyk.io, or api.au.snyk.io). "
                    + "HTTP is allowed only for loopback WireMock tests; credentials, query, fragment, and custom remote ports are not allowed."
            );
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
