cmake_minimum_required(VERSION 3.20)
project(vgi_iroh_cabi_smoke LANGUAGES C)

find_package(vgi_iroh_cabi CONFIG REQUIRED)
add_executable(vgi_iroh_cabi_smoke main.c)
target_link_libraries(vgi_iroh_cabi_smoke PRIVATE vgi_iroh::cabi)

enable_testing()
add_test(NAME vgi_iroh_cabi_smoke COMMAND vgi_iroh_cabi_smoke)
