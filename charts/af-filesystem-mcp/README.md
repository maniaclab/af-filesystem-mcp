# af-filesystem-mcp Helm chart

Deploys af-filesystem-mcp over HTTP transport in broker mode -- the only
HTTP mode this chart supports. See the top-level `CLAUDE.md` for the
security model (per-user impersonated subprocess, path confinement) and
`values.yaml` for the full set of configurable settings.

## Prerequisites (not created by this chart)

- A broker-issued identity JWT provider configured for this backend in
  af-mcp-platform (`identityProviders[].targetOptions.af-filesystem-mcp.
  includePosix: true`, `aggregator.backends` entry with `auth_type: bearer`).
- Two PersistentVolumeClaims in this chart's namespace, bound read-only to
  the AF's shared homes and data storage (`homes.existingClaim`,
  `data.existingClaim`) -- see `values.yaml`'s comments on each for the
  exact NFS export / mount mechanism each needs, and
  maniaclab/af-mcp-platform#188 for the platform-wiring checklist.

## Install

```bash
helm install af-filesystem-mcp ./charts/af-filesystem-mcp \
  --set auth.broker.brokerUrl=http://af-mcp-platform-broker.mcp.svc.cluster.local:8080 \
  --set homes.existingClaim=af-filesystem-mcp-homes \
  --set data.existingClaim=af-filesystem-mcp-data
```

## Lint / smoke render

```bash
helm lint charts/af-filesystem-mcp -f charts/af-filesystem-mcp/ci/broker-values.yaml
helm template smoke charts/af-filesystem-mcp -f charts/af-filesystem-mcp/ci/broker-values.yaml
```
