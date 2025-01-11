# The naming scheme of package is "<vendor>.<id>".
# 
# The policy location of the corresponding policy file should be "<vendor>/<id>.rego".
#

package oeas.virtcca

default allow = false

allow {
    input["tee"] == "vcca"
}