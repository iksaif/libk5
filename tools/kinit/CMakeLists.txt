add_executable (kinit kinit.c)
target_link_libraries (kinit k5 ${KRB5_LIBRARIES})
include_directories (${k5_SOURCE_DIR} ${KRB5_INCLUDE_DIRS})

install(TARGETS kinit
  COMPONENT tools
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
  ARCHIVE DESTINATION lib
)