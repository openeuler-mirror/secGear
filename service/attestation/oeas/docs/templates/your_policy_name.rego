package attestation
import rego.v1

expect_keys := ["vcca.cvm.rim"]
input_keys := object.keys(input)

output[exist] := input[exist] if {
    some exist in expect_keys
    exist in input_keys
}
