# Third-Party Notices

`packet-drop-exporter` depends on third-party Go modules whose licenses remain in effect. The project's MIT license does not replace those terms.

Release archives contain a generated `third_party_licenses/` directory with the top-level license, notice, copying, and copyright files from every runtime module reported by:

```sh
go list -deps -json ./cmd/packet-drop-exporter
```

Regenerate the bundle locally with:

```sh
make licenses
```

The release SBOM provides the corresponding module versions. Review both the SBOM and the bundled license texts when redistributing release binaries or container images.
