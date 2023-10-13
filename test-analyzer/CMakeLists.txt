add_executable(test-analyzer
  test.cpp
  )

llvm_map_components_to_libnames(llvm_libs support core irreader)

target_link_libraries(test-analyzer
  PRIVATE
  nlohmann_json::nlohmann_json
  clangAST
  clangASTMatchers
  clangBasic
  clangFrontend
  clangSerialization
  clangTooling
  )

  install(TARGETS test-analyzer RUNTIME DESTINATION bin) 