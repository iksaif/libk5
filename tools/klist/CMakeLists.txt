add_executable (klist klist.c)
target_link_libraries (klist k5 ${KRB5_LIBRARIES})
include_directories (${k5_SOURCE_DIR} ${KRB5_INCLUDE_DIRS})
