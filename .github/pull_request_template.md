## Summary

Describe the problem and the chosen solution.

## Verification

List the exact checks performed and any checks that were not run.

## Compatibility and Operations

Describe changes to metrics, labels, configuration, capabilities, kernel support, performance, privacy, or resource usage. Write `None` when there is no impact.

## Checklist

- [ ] Tests cover the changed behavior.
- [ ] `go test ./...`, `go test -race ./...`, and `go vet ./...` pass.
- [ ] Docker/Linux verification was run when BPF or kernel behavior changed.
- [ ] Documentation and examples are updated in English.
- [ ] Runtime dependency license output was reviewed when Go dependencies changed.
- [ ] No generated BPF files, secrets, private host data, packet payloads, or raw kernel addresses are included.
- [ ] The implementation plan and verification record are updated when applicable.
