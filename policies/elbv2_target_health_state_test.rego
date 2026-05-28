package compliance_framework.elbv2_target_health_state_test

import data.compliance_framework.elbv2_target_health_state as policy

target_health_input(state) := {
	"schema_version": "v1",
	"source": "aws-elbv2",
	"account": {"account_id": "123456789012"},
	"region": {"name": "us-east-1"},
	"resource": {
		"id": "targetgroup/my-tg/abc123/i-0123",
		"arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-tg/abc123",
		"type": "target-health",
	},
	"config": {
		"target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-tg/abc123",
		"target_id": "i-0123456789abcdef0",
		"target_health_state": state,
	},
}

test_healthy_target_has_no_violation if {
	count(policy.violation) == 0 with input as target_health_input("healthy")
}

test_unhealthy_target_has_violation if {
	count(policy.violation) == 1 with input as target_health_input("unhealthy")
}

test_unhealthy_exception_has_no_violation if {
	count(policy.violation) == 0 with input as target_health_input("unhealthy") with data.allowed_unhealthy_target_ids as ["i-0123456789abcdef0"]
}

test_draining_target_has_no_violation if {
	count(policy.violation) == 0 with input as target_health_input("draining")
}

test_unused_target_has_no_violation if {
	count(policy.violation) == 0 with input as target_health_input("unused")
}

test_initial_target_has_no_violation if {
	count(policy.violation) == 0 with input as target_health_input("initial")
}

test_unavailable_target_has_no_violation_by_default if {
	count(policy.violation) == 0 with input as target_health_input("unavailable")
}

test_unavailable_target_has_violation_when_configured if {
	count(policy.violation) == 1 with input as target_health_input("unavailable") with data.treat_unavailable_as_failure as true
}

test_unavailable_exception_has_no_violation_when_configured if {
	count(policy.violation) == 0 with input as target_health_input("unavailable") with data.treat_unavailable_as_failure as true with data.allowed_unhealthy_target_ids as ["i-0123456789abcdef0"]
}

test_non_target_health_record_skipped if {
	inp := {"resource": {
		"type": "loadbalancer",
		"id": "app/my-alb/abc123",
	}}

	count(policy.violation) == 0 with input as inp
	policy.skip_reason with input as inp
}
