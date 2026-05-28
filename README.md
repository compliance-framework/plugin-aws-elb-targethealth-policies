# AWS ELBv2 target health policies

Standalone OPA/Rego policy bundle for target health evidence emitted by the `aws-elbv2` Compliance Framework plugin.

## Input schema

This bundle evaluates documents where `input.resource.type == "target-health"`.

```json
{
  "schema_version": "v1",
  "source": "aws-elbv2",
  "account": { "account_id": "123456789012" },
  "region": { "name": "us-east-1" },
  "resource": {
    "id": "targetgroup/my-tg/abc123/i-0123",
    "arn": "arn:aws:elasticloadbalancing:...:targetgroup/my-tg/abc123",
    "type": "target-health"
  },
  "config": {
    "target_group_arn": "arn:aws:elasticloadbalancing:...:targetgroup/my-tg/abc123",
    "target_id": "i-0123456789abcdef0",
    "target_health_state": "unhealthy"
  }
}
```

## Implemented policy packages

| Package | Purpose | Metric ID | Controls |
| --- | --- | --- | --- |
| `compliance_framework.elbv2_target_health_state` | Flags registered targets reporting `unhealthy`, and optionally `unavailable`, unless the target is an approved exception. | `ELB_TARGET_HEALTH` | `ctrl-a1-1-009`, `ctrl-a1-2-007` |

The policy skips non-`target-health` records. For target-health records with recognized states, `unhealthy` fails unless allowed, `unavailable` only fails when `data.treat_unavailable_as_failure` is true, and recognized non-failing states such as `healthy`, `draining`, `unused`, and `initial` do not produce violations. Missing or unrecognized `target_health_state` values are skipped with `skip_reason` rather than treated as compliant.

## Policy data

Configurable policy defaults are stored in `policies/data.json` as flattened top-level data values. The agent may override them at runtime via its `policy_data` block.

| Name | Default | Meaning |
| --- | --- | --- |
| `data.allowed_unhealthy_target_ids` | `[]` | Target IDs approved as exceptions when they report `unhealthy` or configured-failing `unavailable` states. |
| `data.treat_unavailable_as_failure` | `false` | When `true`, targets reporting `unavailable` produce a violation unless their target ID is allowed. |

## Testing

```shell
opa fmt --list --fail policies
opa check --strict policies
opa test policies
```

## Bundling

```shell
make build
```
