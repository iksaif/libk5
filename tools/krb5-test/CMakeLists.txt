set(krb5_test_SRCS krb5-test.c)

if (WIN32 AND MSVC)
  set(krb5_test_SRCS ${krb5_test_SRCS} ../windows/getopt.c ../windows/getopt_long.c)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../windows)
endif (WIN32 AND MSVC)

add_executable (krb5-test ${krb5_test_SRCS})
target_link_libraries (krb5-test k5 ${KRB5_LIBRARIES})
if (WIN32)
  target_link_libraries (krb5-test wsock32 ws2_32)
endif()
include_directories (${k5_SOURCE_DIR} ${KRB5_INCLUDE_DIRS})

install(TARGETS krb5-test
  COMPONENT tools
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
  ARCHIVE DESTINATION lib
)

if (WIN32)
  install(FILES krb5-test.bat
    COMPONENT tools
    DESTINATION bin
  )
endif (WIN32)