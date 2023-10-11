add_executable(firmware-analyzer
  AnalyzeEDK2.cpp
  Visitor.cpp
  )

llvm_map_components_to_libnames(llvm_libs support core irreader)

target_link_libraries(firmware-analyzer
  PRIVATE
  nlohmann_json::nlohmann_json
  clangAST
  clangASTMatchers
  clangBasic
  clangFrontend
  clangSerialization
  clangTooling
  )

  install(TARGETS firmware-analyzer RUNTIME DESTINATION bin) 