cmake_minimum_required(VERSION 3.22)
project(neebles_secrets_desktop LANGUAGES CXX)

# No host Qt fallback; F10 must compile through Esbirro's controlled Qt 6.8.2 world.
if(NOT DEFINED NEEBLES_SECRETS_CONTROLLED_SYSROOT OR
   NOT CMAKE_SYSROOT STREQUAL NEEBLES_SECRETS_CONTROLLED_SYSROOT OR
   NOT IS_DIRECTORY "${NEEBLES_SECRETS_CONTROLLED_SYSROOT}/usr/include")
    message(FATAL_ERROR "NEEBLES Secrets requires Esbirro controlled Qt sysroot")
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_SKIP_BUILD_RPATH ON)
set(CMAKE_SKIP_INSTALL_RPATH ON)
find_package(Qt6 6.8.2 EXACT REQUIRED COMPONENTS Widgets Network)
add_executable(neebles-secrets-desktop main.cpp MainWindow.cpp MainWindow.h BackupIpc.cpp BackupIpc.h PortableExportIpc.cpp PortableExportIpc.h)
target_link_libraries(neebles-secrets-desktop PRIVATE Qt6::Widgets Qt6::Network)
target_compile_options(neebles-secrets-desktop PRIVATE -Wall -Wextra -Wpedantic)
get_filename_component(NEEBLES_SECRETS_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
install(TARGETS neebles-secrets-desktop RUNTIME DESTINATION bin)
install(FILES "${NEEBLES_SECRETS_ROOT}/manifest.json" DESTINATION ".")
install(DIRECTORY "${NEEBLES_SECRETS_ROOT}/assets/" DESTINATION assets FILES_MATCHING PATTERN "*.png")
