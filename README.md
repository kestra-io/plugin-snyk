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

The trigger emits one issue per polling evaluation. A backlog is drained at one issue per interval (40 issues can take up to 10 hours at the default PT15M). For safe key-value storage, a poll is limited to 20,000 tracked IDs, 100 pending new issues, and 900 KiB of serialized state; exceeding a cap fails without silently dropping issues. Use a narrower severity filter or ListIssues for large exports.

See [plugin documentation](src/main/resources/doc/io.kestra.plugin.snyk.md) for connection properties, fetch modes, trigger behavior, limits, and runnable examples.

## Development

```shell
./gradlew test
./gradlew lintPluginDocs
./gradlew build
```

## License

Apache 2.0. See [LICENSE](LICENSE).
