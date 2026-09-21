# Security Policy

## Supported Versions

The project is pre-release. Only the latest code on the default branch is currently considered for security fixes. A version support table will be added after stable releases exist.

## Reporting a Vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's private vulnerability reporting for this repository. If private reporting is unavailable, contact the maintainer through the contact method listed on the repository owner's GitHub profile without including exploit details in a public message.

Include, when possible:

- The affected revision or version.
- Kernel, distribution, and architecture.
- Deployment method and granted capabilities.
- Reproduction steps or a minimal proof of concept.
- Expected impact and any known mitigation.

Do not include real packet payloads, credentials, private addresses, raw kernel addresses, or other sensitive host data unless a secure channel has been established.

The maintainer will acknowledge reports when practical, investigate them, and coordinate disclosure and fixes based on severity. No response-time SLA is currently offered.

## Security Boundaries

The exporter loads eBPF, reads kernel BTF, and may read kallsyms. It therefore requires elevated Linux capabilities. Keep the HTTP listener on loopback unless an authenticated, access-controlled proxy protects it. Review all capability and mount requirements before deployment.
