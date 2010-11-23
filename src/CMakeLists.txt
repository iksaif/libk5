project(k5)

option(K5_STATIC "build a static library [default: off]" OFF)

add_library (k5 SHARED k5.c base64.c mslsa.c)
add_library (k5s STATIC k5.c base64.c mslsa.c)

target_link_libraries (k5 ${KRB5_LIBRARIES})
include_directories (${KRB5_INCLUDE_DIRS})

set_target_properties(k5 PROPERTIES
                      VERSION ${K5_LIB_MAJOR_VERSION}.${K5_LIB_MINOR_VERSION}.${K5_LIB_PATCH_VERSION}
                      SOVERSION ${K5_LIB_MAJOR_VERSION}
                      DEFINE_SYMBOL K5_MAKEDLL
                      )

install(FILES k5.h
  COMPONENT devel
  DESTINATION include
)

install(TARGETS k5 k5s
  COMPONENT libraries
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
  ARCHIVE DESTINATION lib
)
