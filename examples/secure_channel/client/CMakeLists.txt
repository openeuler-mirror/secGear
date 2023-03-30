#set host exec name
set(OUTPUT sc_client)
#set host src code
set(SOURCE_FILE ${CMAKE_CURRENT_SOURCE_DIR}/client.c)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-maybe-uninitialized -fPIE")

if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
endif()
add_executable(${OUTPUT} ${SOURCE_FILE})
target_include_directories(${OUTPUT} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${SECGEAR_INSTALL_DIR})
if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
    target_link_directories(${OUTPUT} PRIVATE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
endif()
target_link_libraries(${OUTPUT} pthread csecure_channel)

set_target_properties(${OUTPUT} PROPERTIES SKIP_BUILD_RPATH TRUE)

install(TARGETS  ${OUTPUT}
        RUNTIME
        DESTINATION ${CMAKE_BINARY_DIR}/bin/
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)
