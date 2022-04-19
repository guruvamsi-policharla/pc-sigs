add_subdirectory(lib)

set(BENCH pcsig_bench)
foreach(item IN ITEMS ${BENCH})
	add_executable(${item} ${item}.cpp)
	target_link_libraries(${item} PRIVATE PCSIGlib mcl::mcl)
	target_include_directories(${item} PUBLIC
						  ${CMAKE_BINARY_DIR}
                          ${CMAKE_CURRENT_SOURCE_DIR}/lib
                          )
	set_target_properties(${item} PROPERTIES
		CXX_STANDARD 11
		CXX_STANDARD_REQUIRED YES
	CXX_EXTENSIONS NO)
	target_compile_options(${item} PRIVATE ${MCL_COMPILE_OPTIONS})
	target_compile_definitions(${item} PRIVATE MCL_DONT_EXPORT)
endforeach()

set(BENCH2 linkpcsig_bench)
foreach(item IN ITEMS ${BENCH2})
	add_executable(${item} ${item}.cpp)
	target_link_libraries(${item} PRIVATE LINKPCSIGlib mcl::mcl)
	target_include_directories(${item} PUBLIC
						  ${CMAKE_BINARY_DIR}
                          ${CMAKE_CURRENT_SOURCE_DIR}/lib
                          )
	set_target_properties(${item} PROPERTIES
		CXX_STANDARD 11
		CXX_STANDARD_REQUIRED YES
	CXX_EXTENSIONS NO)
	target_compile_options(${item} PRIVATE ${MCL_COMPILE_OPTIONS})
	target_compile_definitions(${item} PRIVATE MCL_DONT_EXPORT)
endforeach()