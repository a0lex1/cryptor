cmake_minimum_required (VERSION 3.15)
project ("_spraytest_")

# MFC 2=shared, 1=static
set(CMAKE_MFC_FLAG 2)
#add_definitions(-D_AFXDLL)
#add_definitions(-D_UNICODE)
add_definitions(/D_WIN32_WINNT=0x0603)
#set(Boost_USE_STATIC_RUNTIME OFF)
#set(CMAKE_POSITION_INDEPENDENT_CODE ON) ### ?
include_directories(src/)
include_directories(extra/)
include_directories(include_spraygen/)

file(GLOB_RECURSE spraybuild_SOURCES gened_code.cpp)
file(GLOB_RECURSE src_SOURCES src/* ./*.h)
file(GLOB_RECURSE extra_SOURCES FOLLOW_SYMLINKS extra/*)
set_property(SOURCE ${spraybuild_SOURCES} PROPERTY VS_SETTINGS
  $<$<CONFIG:Debug>:ExcludedFromBuild=true>
  $<$<CONFIG:Release>:ExcludedFromBuild=true>)  
set_property(SOURCE ${src_SOURCES} PROPERTY VS_SETTINGS
  $<$<CONFIG:DebugSprayed>:ExcludedFromBuild=true>
  $<$<CONFIG:ReleaseSprayed>:ExcludedFromBuild=true>)
set_property(SOURCE ${extra_SOURCES} PROPERTY VS_SETTINGS
  $<$<CONFIG:DebugSprayed>:ExcludedFromBuild=true>
  $<$<CONFIG:ReleaseSprayed>:ExcludedFromBuild=true>)
source_group(TREE ${CMAKE_SOURCE_DIR} FILES ${src_SOURCES})
source_group(TREE ${CMAKE_SOURCE_DIR} FILES ${extra_SOURCES})


# fix something cmake can't on its own - must be here, not at bottom
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug,DebugSprayed>:Debug>")

add_executable (_spraytest_ WIN32 ${src_SOURCES} ${spraybuild_SOURCES} ${extra_SOURCES})
add_custom_command(
    TARGET _spraytest_ PRE_BUILD
    COMMAND echo (Reserved message)
)

target_compile_definitions(_spraytest_ PRIVATE
  $<$<CONFIG:DebugSprayed>:SPRAYED_BUILD=1>
  $<$<CONFIG:ReleaseSprayed>:SPRAYED_BUILD=1>
)


#sspi.h needs this
target_compile_definitions(_spraytest_ PRIVATE SECURITY_WIN32)


# fix things cmake can't fix on its own, make it default
target_compile_options(_spraytest_ PRIVATE $<$<CONFIG:DebugSprayed>:/Od /RTC1 /Ob0 /Zi>)
target_link_options(_spraytest_ PRIVATE $<$<CONFIG:DebugSprayed>:/DEBUG> /MAP)
target_link_options(_spraytest_ PRIVATE /SUBSYSTEM:CONSOLE)

set_property(TARGET _spraytest_ PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

# whole program optimization
#set_target_properties(_spraytest_ PROPERTIES COMPIILE_OPTIONS "$<$<CONFIG:Release>:/GL>")

