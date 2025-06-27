find_package(GTest REQUIRED)

add_executable(tests
    main.cpp
)

target_link_libraries(tests PRIVATE
    packetparser
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

set_target_properties(tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_test(NAME parser_tests COMMAND tests)