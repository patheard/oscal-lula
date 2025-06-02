package validations

import rego.v1

# METADATA
# title: Findings Relevant
# description: A function that returns the Prowler findings relevant to a specific compliance control.
# related_resources:
# - https://github.com/prowler-cloud/prowler
findings_relevant(findings, compliance_id, control_id) := result if {
	result := [finding |
		some finding in findings
		
		nist_controls := finding.Compliance[compliance_id]
		nist_controls != null

		controls := [control | some control in nist_controls; startswith(lower(control), control_id)]
		count(controls) > 0
	]
} else := []

# METADATA
# title: Findings Failed
# description: A function that returns the Prowler findings that have failed based on a status and set of severities.
# related_resources:
# - https://github.com/prowler-cloud/prowler
findings_failed(findings, status, severity) := result if {
    result := [finding |
        some finding in findings
        finding.Status != status
        finding.Severity in severity
    ]
} else := []

# METADATA
# title: Findings Message (invalid)
# description: A function that returns a failed validation message with the failed check IDs
findings_msg(findings_relevant, findings_failed, is_valid) := msg if {
	is_valid == false
	failed_checks := concat(", ", [finding.CheckID | some finding in findings_failed])
	msg := sprintf("Failed compliance checks: %v", [failed_checks])
}

# METADATA
# title: Findings Message (valid)
# description: A function that returns a successful validation message with the passed check IDs
findings_msg(findings_relevant, findings_failed, is_valid) := msg if {
	is_valid == true
	passed_checks := concat(", ", [finding.CheckID | some finding in findings_relevant])
	msg := sprintf("All compliance checks passed: %v", [passed_checks])
}
