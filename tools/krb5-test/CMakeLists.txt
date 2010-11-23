add_executable (krb5-test krb5-test.c)
target_link_libraries (krb5-test k5 ${KRB5_LIBRARIES})
include_directories (${k5_SOURCE_DIR} ${KRB5_INCLUDE_DIRS})
