if(TARGET vgi_iroh::cabi)
  return()
endif()

get_filename_component(_VGI_IROH_CABI_PREFIX "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)

if(WIN32)
  set(_VGI_IROH_CABI_LIBRARY "${_VGI_IROH_CABI_PREFIX}/lib/vgi_iroh_cabi.lib")
else()
  set(_VGI_IROH_CABI_LIBRARY "${_VGI_IROH_CABI_PREFIX}/lib/libvgi_iroh_cabi.a")
endif()
if(NOT EXISTS "${_VGI_IROH_CABI_LIBRARY}")
  message(FATAL_ERROR "vgi-iroh-cabi archive is missing ${_VGI_IROH_CABI_LIBRARY}")
endif()

add_library(vgi_iroh::cabi STATIC IMPORTED)
set_target_properties(vgi_iroh::cabi PROPERTIES
  IMPORTED_LOCATION "${_VGI_IROH_CABI_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${_VGI_IROH_CABI_PREFIX}/include"
)

# Rust reports these with `--print=native-static-libs`. They are part of the
# static-library contract and must follow the archive on the final link line.
if(WIN32)
  file(GLOB _VGI_IROH_WINDOWS_IMPORT_LIBS
    "${_VGI_IROH_CABI_PREFIX}/lib/windows.*.lib")
  if(NOT _VGI_IROH_WINDOWS_IMPORT_LIBS)
    message(FATAL_ERROR "vgi-iroh-cabi archive contains no versioned Windows import libraries")
  endif()
  target_link_libraries(vgi_iroh::cabi INTERFACE
    ${_VGI_IROH_WINDOWS_IMPORT_LIBS}
    advapi32 bcrypt crypt32 dbghelp iphlpapi ncrypt ntdll ole32 oleaut32
    secur32 shell32 user32 userenv ws2_32
  )
elseif(APPLE)
  find_library(_VGI_IROH_SECURITY Security REQUIRED)
  find_library(_VGI_IROH_SYSTEM_CONFIGURATION SystemConfiguration REQUIRED)
  find_library(_VGI_IROH_CORE_FOUNDATION CoreFoundation REQUIRED)
  find_library(_VGI_IROH_FOUNDATION Foundation REQUIRED)
  target_link_libraries(vgi_iroh::cabi INTERFACE
    "${_VGI_IROH_SECURITY}"
    "${_VGI_IROH_SYSTEM_CONFIGURATION}"
    "${_VGI_IROH_CORE_FOUNDATION}"
    "${_VGI_IROH_FOUNDATION}"
    iconv
    objc
  )
elseif(UNIX)
  find_package(Threads REQUIRED)
  target_link_libraries(vgi_iroh::cabi INTERFACE
    Threads::Threads ${CMAKE_DL_LIBS} m rt util
  )
else()
  message(FATAL_ERROR "vgi-iroh-cabi has no native static-link contract for this platform")
endif()

unset(_VGI_IROH_CABI_LIBRARY)
unset(_VGI_IROH_CABI_PREFIX)
unset(_VGI_IROH_WINDOWS_IMPORT_LIBS)
