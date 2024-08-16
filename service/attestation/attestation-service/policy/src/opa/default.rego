# if create a new rego file, "output" should exist,
# package name should be "attestation"
package attestation
import rego.v1

input_keys := object.keys(input)

output[exist] := input[exist] if {
	some exist in input_keys
}
