package attestation
import future.keywords.if

allow := true if {
    input["itrustee.ta_img"] != null
    input["itrustee.ta_mem"] != null
} else := false

ta_img := input["itrustee.ta_img"] if {
    input["itrustee.ta_img"] != null
} else := null

ta_mem := input["itrustee.ta_mem"] if {
    input["itrustee.ta_mem"] != null
} else := null

#output and output.allow must exist
output := {
    "allow": allow,
    "itrustee.ta_img": ta_img,
    "itrustee.ta_mem": ta_mem
}