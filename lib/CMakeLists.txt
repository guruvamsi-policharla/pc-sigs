add_library(PCSIGlib pcsig.cpp)
add_library(LINKPCSIGlib linkpcsig.cpp)
target_link_libraries(PCSIGlib PRIVATE mcl::mcl)
target_link_libraries(LINKPCSIGlib PRIVATE mcl::mcl)