# Kestra Snyk Plugin

## What

This repository implements a Kestra plugin for retrieving Snyk organization issues and starting flows when new issues are detected. The plugin lives in the `io.kestra.plugin.snyk` package.

## Why

Security workflows need a repeatable way to query Snyk issue data, export large result sets, and react to newly detected issues without embedding API credentials in flow code or task output.

## How

### Architecture

This is a single-module Java plugin built with Gradle and Kestra's plugin conventions.

- `SnykConnection` owns shared REST API configuration, URL validation, request construction, pagination, JSON:API parsing, and actionable HTTP error handling.
- `ListIssues` implements the `RunnableTask<FetchOutput>` task with `FETCH`, `FETCH_ONE`, `STORE`, and `NONE` modes.
- `IssueTrigger` polls an organization and emits one execution for each newly detected issue. It uses namespace key-value storage for a known-ID baseline and a pending queue.
- `src/main/resources/doc/io.kestra.plugin.snyk.md` contains the plugin's user-facing documentation and examples.

### Important behavior and constraints

- Keep Snyk tokens marked as secret properties and excluded from generated `toString` output. Never log tokens or raw API response bodies.
- Remote API URLs must remain on the official regional Snyk API hosts over HTTPS. HTTP is only supported for loopback-based WireMock tests. Pagination links must stay on the configured origin and organization-issues endpoint.
- Preserve the 100-issue API page size and guard against repeated pagination links and excessive page counts.
- The trigger's first successful scan establishes a baseline. Metadata and ID shards use a one-year TTL, independent of the polling interval. ID snapshots are stored in shards of at most 5,000 IDs, unchanged snapshots are reused while draining the queue, and replaced generations are deleted directly by their recorded shard keys after the new state pointer is committed.
- If state expires or a shard is missing, the trigger warns that pending issues and issues created during the unavailable period may be skipped, then establishes a new baseline instead of failing every poll.
- The trigger queues at most 100 new issues per scan and leaves overflow IDs out of the saved known-ID set so a later scan can discover them after the pending queue drains.

### Validation

Before submitting changes, run:

```shell
./gradlew clean test lintPluginDocs build
```

The tests use WireMock and should not require a live Snyk account or API token. Add regression tests for API parsing/pagination, URL validation, output modes, trigger state changes, overflow recovery, and shard lifecycle when modifying those behaviors.

## References

- https://kestra.io/docs/plugin-developer-guide
- https://kestra.io/docs/plugin-developer-guide/contribution-guidelines
