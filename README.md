# Kestra Snyk Plugin

Integrate Snyk security issue data into Kestra workflows with the `ListIssues` task and `IssueTrigger`.

## Features

- Query Snyk organization issues through the Snyk REST API.
- Filter issues by effective severity: critical, high, medium, or low.
- Use `FETCH`, `FETCH_ONE`, `STORE`, or `NONE` output modes.
- Automatically follow cursor pagination for full fetches and stored exports.
- Poll for newly detected issues and emit one trigger execution per issue.
- Use a page size of 100 to reduce API calls for issue scans.
- Keep trigger state bounded and isolated by organization and severity filter.
- Configure regional Snyk API endpoints and API versions.

## Quick start

Save your Snyk API token and organization ID as Kestra secrets, then add:

```yaml
id: snyk_issues
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
```

Use `outputs.list_issues.uri` to access the stored Ion file. Set `fetchType: FETCH` to expose the issue objects as `outputs.list_issues.rows`.

## Documentation

The trigger emits one issue per polling evaluation. A backlog is drained at one issue per interval (40 issues can take up to 10 hours at the default PT15M). Each scan queues at most 100 new issues; the remaining new IDs stay out of the known-ID snapshot so later scans can pick them up after the queue drains. Known IDs are stored in shards of at most 5,000 IDs. State metadata and shards use a one-year TTL, independent of the polling interval. Shard generations are reused on queue-drain polls, and unchanged shards are refreshed after half their TTL has elapsed. When a replacement snapshot is committed, stale-generation cleanup is best effort and cleanup failures are logged rather than dropping an already-detected issue. If the state expires or a shard is missing, pending issues and issues created while state was unavailable may be skipped as the trigger establishes a fresh baseline. Use `ListIssues` for large exports.

See [plugin documentation](src/main/resources/doc/io.kestra.plugin.snyk.md) for connection properties, fetch modes, trigger behavior, limits, and runnable examples.

## Development

```shell
./gradlew test
./gradlew lintPluginDocs
./gradlew build
```

## License

Apache 2.0. See [LICENSE](LICENSE).
