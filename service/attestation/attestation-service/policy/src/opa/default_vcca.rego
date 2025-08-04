# package name should be "attestation"
package attestation
import future.keywords.if


#---------------Platform SW Verify Start---------------

# platform_sw_measure_value数据摘取software_components.json的measure_value字段
# software_components.json是platform_token底层组件json文件，随BIOS发行版本带入
# hash_algorithm字段不验证
platform_sw_measure_value := [
    {
        "firware_name": "firmware_name",
        "measurement": "measurement",
        "firmware_version": "firmware_version",
    },
    {
        "firware_name": "firmware_name",
        "measurement": "measurement",
        "firmware_version": "firmware_version",
    }
]

platform_sw_verify := true if {
    input["vcca.is_platform"] == false
} else := input["vcca.platform.measure_value"] == platform_sw_measure_value


# 验证platform sw需自定义policy，可参考本默认策略实现
# 默认策略不验证platform sw，如需验证请注释下一行代码
platform_sw_verify := "Not Verified"
#---------------Platform SW Verify End---------------

allow := true if {
    input["vcca.cvm.rim"] != null
} else := false

rim := input["vcca.cvm.rim"]

# output and output.allow must exist
# 如果不需要验证platform sw，则删除字段"vcca.platform.verify"
output := {
    "allow": allow,
    "vcca.platform.verify": platform_sw_verify,
    "vcca.cvm.rim": rim,
}
