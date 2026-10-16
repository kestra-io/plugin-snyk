# Kestra Snyk Plugin

The Snyk plugin integrates Kestra flows with the Snyk REST API to retrieve organization security issues and trigger flows when new issues are detected.

## Authentication and connection

Store the Snyk API token in a Kestra secret and reference it with `{{ secret('SNYK_API_TOKEN') }}`. The API token is sent in the `Authorization: token <token>` header and is marked as a secret plugin property.

| Property | Default | Description |
| --- | --- | --- |
| `token` | Required | Snyk API token |
| `baseUrl` | `https://api.snyk.io/rest` | Regional REST API base URL, e.g. `https://api.eu.snyk.io/rest` |
| `apiVersion` | `2024-10-15` | Snyk REST API version (sent as the API query parameter `version`) |
| `orgId` | Required | Snyk organization ID |
| `severities` | All severities | Optional list of `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` |

The HTTP client supports Kestra HTTP configuration options. Remote URLs must use one of Snyk's official regional API hosts: `api.snyk.io`, `api.us.snyk.io`, `api.eu.snyk.io`, or `api.au.snyk.io` over HTTPS on the default port. HTTP is accepted only for loopback addresses to support local WireMock tests.

## ListIssues

`io.kestra.plugin.snyk.ListIssues` lists issues from `GET /orgs/{org_id}/issues`. It requests up to 100 issues per page and follows Snyk's cursor pagination links for `FETCH`, `STORE`, and `NONE` modes. The API's `effective_severity_level` filter is used when one or more severities are configured.

### Fetch all critical and high-severity issues

```yaml
id: snyk_list_critical_issues
namespace: company.security

tasks:
  - id: list_issues
    type: io.kestra.plugin.snyk.ListIssues
    token: "{{ secret('SNYK_API_TOKEN') }}"
    orgId: "{{ secret('SNYK_ORG_ID') }}"
    severities:
      - CRITICAL
      - HIGH
    fetchType: FETCH
```

### Fetch modes

- **FETCH** — returns `rows` and `size` for all matching issues across all pages.
- **FETCH_ONE** — returns the first issue in `row` and stops after the first page result; `size` is zero or one.
- **STORE** — writes all matching issues to Kestra internal storage and returns `uri` and `size`.
- **NONE** — traverses the result set and returns only the count.

Use `STORE` for large result sets to avoid returning all issue records as task output.

## IssueTrigger

`io.kestra.plugin.snyk.IssueTrigger` polls the organization on the configured `interval` (default `PT15M`). Its first successful poll establishes a baseline of existing issue IDs to avoid firing once for every historical issue. Later polls emit one execution for each newly detected issue, with `trigger.issueId` and the complete JSON:API issue object in `trigger.issue`.

The trigger stores its baseline and pending issue queue in namespace key-value storage. State is isolated by flow, trigger, organization, API endpoint/version, and severity filter; changing the organization or filter establishes a fresh baseline rather than treating historical issues as new. Known IDs are stored in separate shards of at most 5,000 IDs, so the baseline is not kept in a single ever-growing KV value.

The trigger emits **one execution per polling evaluation**. When a burst creates a backlog, pending issues are drained one per interval (at the default `PT15M`, 40 queued issues can take up to 10 hours to drain). Each scan queues at most 100 newly detected issues. Further new IDs are deliberately left out of the saved known-ID snapshot, allowing later scans to discover them after the queue drains instead of leaving polling stuck in a permanent failure loop. State metadata expires after one year of inactivity. ID shards are written as generations and reused during queue-drain polls; when the known-ID snapshot changes, the pointer is updated before the old generation is deleted. If a shard is missing, the trigger logs a warning and re-establishes a baseline rather than failing every subsequent poll. Use `ListIssues` for full exports.

### Alert on new critical issues

```yaml
id: snyk_alert_on_new_critical
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
    message: "New Snyk issue detected: {{ trigger.issueId }}"
```

## API behavior and errors

- Requests use the configured API version, JSON:API content type, and `limit=100` (the documented maximum for this endpoint).
- Pagination links are followed only when they remain on the configured API origin and the same organization issues endpoint.
- Repeated pagination links and excessive page counts fail explicitly rather than looping forever.
- Empty or malformed response bodies and responses missing the JSON:API `data` array fail explicitly.
- Authentication, authorization, not-found, and rate-limit responses include actionable messages. API tokens and response bodies are not logged by the plugin.
- All API tests use WireMock; no live Snyk account or token is needed to run the test suite.

## Development

Run the tests and plugin documentation checks before submitting changes:

```shell
./gradlew test
./gradlew lintPluginDocs
./gradlew build
```
