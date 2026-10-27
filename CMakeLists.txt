cmake_minimum_required(VERSION 3.20)
project(zcomp VERSION 0.1 LANGUAGES C CXX ASM)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
   NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
  message(FATAL_ERROR "このプロトタイプの実行にはx86-64のLinuxが必要です")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
include(FetchContent)
# 走査器の挙動を再現できるよう、ZydisとそのZycoreサブモジュールをコミットで固定する。
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_ENCODER OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_FORMATTER OFF CACHE BOOL "" FORCE)
FetchContent_Declare(zydis
  GIT_REPOSITORY https://github.com/zyantific/zydis.git
  GIT_TAG a2278f1d254e492f6a6b39f6cb5d1f5d515659dc
  GIT_SUBMODULES dependencies/zycore)
FetchContent_MakeAvailable(zydis)

add_library(zcomp_scan STATIC src/scan.c src/detour.c)
target_include_directories(zcomp_scan PUBLIC src)
target_link_libraries(zcomp_scan PUBLIC Zydis)
target_compile_options(zcomp_scan PRIVATE -Wall -Wextra -Werror)
set_target_properties(zcomp_scan PROPERTIES C_VISIBILITY_PRESET hidden)

add_library(zcomp SHARED src/hook.c src/dispatch.c src/exec.c src/guard.c src/trampoline.S)
target_link_libraries(zcomp PRIVATE zcomp_scan ${CMAKE_DL_LIBS})
# ベクトル/FPU状態を保存していないため、ディスパッチ内でこれらを使うコードを生成させない。
# libcへの再入も避ける。フラグを外す場合は、拡張状態の保存・復元を先に追加する必要がある。
target_compile_options(zcomp PRIVATE
  $<$<COMPILE_LANGUAGE:C>:-Wall;-Wextra;-Werror;-mgeneral-regs-only;-mno-red-zone;-fno-builtin;-fno-stack-protector;-fcf-protection=none>)
target_link_options(zcomp PRIVATE -Wl,-z,defs -Wl,-z,now -Wl,--exclude-libs,ALL)
set_target_properties(zcomp PROPERTIES C_VISIBILITY_PRESET hidden)

enable_testing()
add_executable(scan_test tests/scan_test.c)
target_link_libraries(scan_test PRIVATE zcomp_scan)
target_compile_options(scan_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME scanner COMMAND scan_test)

add_executable(detour_test tests/detour_test.c)
target_link_libraries(detour_test PRIVATE zcomp_scan)
target_compile_options(detour_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME detour_planner COMMAND detour_test)

add_library(preload_test SHARED tests/preload_test.c)
target_compile_options(preload_test PRIVATE -Wall -Wextra -Werror)
find_package(Threads REQUIRED)
add_executable(passthrough_test tests/passthrough.c tests/probes.S)
add_executable(clone_test tests/clone_test.c tests/clone_probes.S tests/probes.S)
add_executable(exec_test tests/exec_test.c tests/probes.S)
foreach(target passthrough_test clone_test exec_test)
  target_include_directories(${target} PRIVATE src)
  target_link_libraries(${target} PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
  target_compile_options(${target} PRIVATE -Wall -Wextra -Werror -UNDEBUG)
endforeach()

# 同じ試験器のnative対照とhook経由を残し、fixture不良や素通りを成功扱いしない。
add_test(NAME native COMMAND passthrough_test)
add_test(NAME passthrough COMMAND ${CMAKE_COMMAND} -E env
  "LD_PRELOAD=$<TARGET_FILE:zcomp>" $<TARGET_FILE:passthrough_test> --hooked)
add_test(NAME clone_native COMMAND clone_test)
add_test(NAME clone_hooked COMMAND ${CMAKE_COMMAND} -E env
  "LD_PRELOAD=$<TARGET_FILE:zcomp>" $<TARGET_FILE:clone_test> --hooked)
add_test(NAME exec_native COMMAND exec_test --native
  $<TARGET_FILE:zcomp> $<TARGET_FILE:preload_test>)
add_test(NAME exec_hooked COMMAND ${CMAKE_COMMAND} -E env
  "LD_PRELOAD=$<TARGET_FILE:zcomp>" $<TARGET_FILE:exec_test> --hooked
  $<TARGET_FILE:zcomp> $<TARGET_FILE:preload_test>)
set_tests_properties(native passthrough clone_native clone_hooked exec_native exec_hooked PROPERTIES TIMEOUT 30)
set_tests_properties(passthrough clone_hooked exec_hooked PROPERTIES SKIP_RETURN_CODE 77)
