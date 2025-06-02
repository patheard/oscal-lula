package validations

import rego.v1

failed_findings(findings, compliance_id, control_id) := result if {
    result := [finding |
        some finding in findings
        finding.Status != "PASS"
        finding.Severity in {"high", "critical"}
		
        nist_controls := finding.Compliance[compliance_id]
        nist_controls != null

        controls := [control | some control in nist_controls; startswith(lower(control), control_id)]
        count(controls) > 0
    ]
} else := []
