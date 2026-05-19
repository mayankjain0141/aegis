# Example custom Rego policy for Aegis
# This policy fires when curl downloads from an unknown host and pipes to bash
package aegis.example

import rego.v1

# deny is true when the command is a remote code execution pattern
deny if {
	input.verbs[_] == "curl"
	input.has_data_flag == false # GET request (not posting data)
	input.evasion_score > 0.3
}

# Allow safe network reads (GET requests to known hosts with no sensitive paths)
allow if {
	input.network_score <= 0.3
	input.has_data_flag == false
	input.has_sensitive == false
	input.has_critical == false
}
