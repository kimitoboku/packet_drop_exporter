# Contributing to packet-drop-exporter

Thank you for considering a contribution. The project welcomes bug reports, documentation improvements, tests, performance work, and implementation changes.

## Before You Start

- Search existing issues before opening a new one.
- Use the bug report template for reproducible defects.
- Open an issue before starting a large feature or a change to public metric semantics.
- Never include packet contents, credentials, private host information, or raw kernel addresses in an issue.
- Read and follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Development Environment

The canonical test environment is the Debian container defined in `Dockerfile`. This keeps BPF generation independent from the contributor's host toolchain.

```sh
docker compose run --build --rm test
```

Native Linux development requires Go, clang, LLVM, libbpf headers, Linux userspace headers, and make. macOS can run Go-only tests, but BPF generation and real attachment must be verified in Linux/Docker.

## Making Changes

1. Keep implementation planning and progress in `docs/implementation-plan.md`; do not create a parallel implementation plan.
2. Add or update tests for behavioral changes.
3. Update `README.md`, `docs/verification.md`, configuration examples, and monitoring assets when public behavior changes.
4. Keep repository documentation in English. Discussions may use any language preferred by participants.
5. Do not edit generated `internal/bpf/drop_bpf*.go` or object files. Change `drop.bpf.c` or its Go definitions, then regenerate with `go generate ./internal/bpf`.
6. Preserve metric names and label semantics unless the change has been discussed as a compatibility break.
7. Run `make licenses` after changing Go runtime dependencies and review the generated manifest for missing or unexpected license files.

## Required Checks

Run at least:

```sh
go test ./...
go test -race ./...
go vet ./...
make licenses
git diff --check
docker compose run --build --rm test
```

Changes to the BPF program, loader, kernel symbolization, or dimensions should also run:

```sh
make docker-integration-test
```

This command is privileged and tests only the current Docker host kernel. Include the kernel, distribution, architecture, and relevant feature-probe results in the pull request.

## Pull Requests

- Keep each pull request focused on one coherent change.
- Explain why the change is needed and how it was verified.
- State any tests that were not run and why.
- Call out changes to metrics, labels, privileges, configuration, resource usage, or supported kernels.
- Avoid unrelated formatting or generated-file changes.

By submitting a contribution, you agree that it is licensed under the repository's [MIT License](LICENSE).
