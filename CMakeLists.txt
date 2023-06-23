cmake_minimum_required(VERSION 3.10)

project(firmware_analyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -frtti")

find_package(LLVM REQUIRED CONFIG)

find_package(Clang REQUIRED CONFIG)

find_package(nlohmann_json 3.2.0 REQUIRED)

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_executable(firmware_analyzer
  AnalyzeEDK2.cpp
  )
target_link_libraries(firmware_analyzer
  PRIVATE
  nlohmann_json::nlohmann_json
  clangAST
  clangASTMatchers
  clangBasic
  clangFrontend
  clangSerialization
  clangTooling
  )

