add_executable (kvno kvno.c)
target_link_libraries (kvno k5 ${KRB5_LIBRARIES})
include_directories (${k5_SOURCE_DIR} ${KRB5_INCLUDE_DIRS})
