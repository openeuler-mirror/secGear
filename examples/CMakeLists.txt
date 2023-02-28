add_custom_target(copy ALL
	COMMAND mkdir -p ${CMAKE_BINARY_DIR}/inc/secGear
	COMMAND cp ${LOCAL_ROOT_PATH}/inc/host_inc/*.h ${CMAKE_BINARY_DIR}/inc/secGear/
	COMMAND cp ${LOCAL_ROOT_PATH}/inc/enclave_inc/*.h ${CMAKE_BINARY_DIR}/inc/secGear/)

if(CC_GP)
	add_custom_command(TARGET copy
		POST_BUILD
		COMMAND cp ${LOCAL_ROOT_PATH}/inc/host_inc/gp/*.edl ${CMAKE_BINARY_DIR}/inc/secGear/
		COMMAND cp ${LOCAL_ROOT_PATH}/inc/host_inc/gp/*.h ${CMAKE_BINARY_DIR}/inc/secGear/
		COMMAND cp ${LOCAL_ROOT_PATH}/inc/enclave_inc/gp/*.h ${CMAKE_BINARY_DIR}/inc/secGear/
		COMMAND cp ${LOCAL_ROOT_PATH}/inc/enclave_inc/gp/itrustee/*.h ${CMAKE_BINARY_DIR}/inc/secGear/)
	add_subdirectory(seal_data)
	add_subdirectory(helloworld)
	add_subdirectory(switchless)
	#add_subdirectory(secure_channel)
	#add_subdirectory(lrt)
endif()

if(CC_SGX)
	add_custom_command(TARGET copy
		POST_BUILD
		COMMAND cp ${LOCAL_ROOT_PATH}/inc/host_inc/sgx/*.h ${CMAKE_BINARY_DIR}/inc/secGear/
		COMMAND cp ${LOCAL_ROOT_PATH}/inc/host_inc/sgx/*.edl ${CMAKE_BINARY_DIR}/inc/secGear/
		COMMAND cp ${LOCAL_ROOT_PATH}/inc/enclave_inc/sgx/*.h ${CMAKE_BINARY_DIR}/inc/secGear/)
	add_subdirectory(seal_data)
	add_subdirectory(helloworld)
	add_subdirectory(switchless)
	#add_subdirectory(secure_channel)
	#add_subdirectory(tls_enclave)
	#add_subdirectory(lrt)
endif()

if(CC_PL)
	add_custom_command(TARGET copy
		POST_BUILD
		COMMAND cp ${LOCAL_ROOT_PATH}/inc/host_inc/penglai/*.h ${CMAKE_BINARY_DIR}/inc/secGear/
		COMMAND cp ${LOCAL_ROOT_PATH}/inc/host_inc/penglai/*.edl ${CMAKE_BINARY_DIR}/inc/secGear/
		COMMAND cp ${LOCAL_ROOT_PATH}/inc/enclave_inc/penglai/*.h ${CMAKE_BINARY_DIR}/inc/secGear/)
	# add_subdirectory(seal_data)
	add_subdirectory(helloworld)
	#add_subdirectory(tls_enclave)
	#add_subdirectory(lrt)
endif()
