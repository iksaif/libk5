add_executable (kdestroy kdestroy.c)
target_link_libraries (kdestroy k5 ${KRB5_LIBRARIES})
include_directories (${k5_SOURCE_DIR} ${KRB5_INCLUDE_DIRS})

install(TARGETS kdestroy
  COMPONENT tools
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
  ARCHIVE DESTINATION lib
)