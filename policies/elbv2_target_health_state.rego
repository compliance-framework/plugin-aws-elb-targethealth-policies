package compliance_framework.elbv2_target_health_state

# METADATA
# title: ELBv2 target is healthy
# description: Checks whether a registered target is healthy, or is an approved exception.
# custom:
#   metric_ids:
#     - ELB_TARGET_HEALTH
#   controls:
#     - ctrl-a1-1-009
#     - ctrl-a1-2-007

# risk_templates is read by the plugin during Init (InitWithSubjectsAndRisksFromPolicies)
# to register the risks this policy can raise. Every policy file MUST declare it.
risk_templates := [{
	"name": "Load balancer target is unhealthy",
	"title": "Unhealthy Targets Reduce Capacity and Threaten Availability",
	"statement": "A registered target reporting an unhealthy state is not serving traffic, reducing effective capacity. If unhealthy targets are left unremediated, a few more failures can exhaust capacity and cause an outage, breaching availability commitments.",
	"likelihood_hint": "medium",
	"impact_hint": "medium",
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-754",
		"title": "Improper Check for Unusual or Exceptional Conditions",
		"url": "https://cwe.mitre.org/data/definitions/754.html",
	}],
	"remediation": {
		"title": "Remediate or formally except unhealthy targets",
		"description": "Investigate and restore the unhealthy target (or replace it), or record an approved exception if the state is expected.",
		"tasks": [
			{"title": "Diagnose why the target fails its health check and restore service"},
			{"title": "Replace or deregister targets that cannot be recovered"},
			{"title": "Record an approved exception for intentionally unhealthy targets"},
		],
	},
}]

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
target_id := object.get(config, "target_id", "unknown")
state := lower(object.get(config, "target_health_state", ""))
allowed := data.allowed_unhealthy_target_ids
treat_unavailable_as_failure := data.treat_unavailable_as_failure
recognized_target_health_states := {"healthy", "unhealthy", "draining", "unused", "initial", "unavailable"}

skip_reason := sprintf("Resource type %q is not a target health record; this policy only applies to target-health records.", [resource_type]) if {
	not resource_type == "target-health"
}

skip_reason := sprintf("Target %s has unrecognized or missing target health state %q.", [target_id, state]) if {
	resource_type == "target-health"
	not state in recognized_target_health_states
}

title := sprintf("Validate target health for %s", [target_id])
description := sprintf("Target %s reports health state %q.", [target_id, state])

violation[{"id": "target_unhealthy"}] if {
	resource_type == "target-health"
	state == "unhealthy"
	not target_id in allowed
}

violation[{"id": "target_unavailable"}] if {
	resource_type == "target-health"
	treat_unavailable_as_failure == true
	state == "unavailable"
	not target_id in allowed
}
