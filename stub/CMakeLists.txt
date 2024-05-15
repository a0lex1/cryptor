cmake_minimum_required (VERSION 3.15)
project ("__stub1__")

#if(ANTIEMU) # good stub
#message(STATUS "ANTIEMU: will be ANTIEMU_${ANTIEMU}")
#else()
#message(FATAL_ERROR "ANTIEMU must be /D")
#endif()

add_compile_options($<$<CXX_COMPILER_ID:MSVC>:/MP>)

# MFC 2=shared, 1=static
#set(CMAKE_MFC_FLAG 2)  # provoked MSB8041 on vmware vs2022, disabled, date: Tue 15 aug 2023
#add_definitions(-D_AFXDLL)
#add_definitions(-D_UNICODE)
add_definitions(/D_WIN32_WINNT=0x0603)
#set(CMAKE_POSITION_INDEPENDENT_CODE ON) ### ?
include_directories(src/)
include_directories(include_spraygen/)

file(GLOB _src_SOURCES
  payload_info.h res.info.h cryptbin.keys.h exports.h payload.binhex.h string_hashes.h
  *.cpp module.def
)
file(GLOB_RECURSE src_SOURCES src/*.cpp src/*.h)
file(GLOB_RECURSE crafted_SOURCES src_crafted/*.cpp src_crafted/*.h)
file(GLOB_RECURSE spraybuild_SOURCES
  gened_code.cpp gened_code.h gened_vars.h gened_substitutions.h gened_headers.h
  spraytab.h
)
file(GLOB_RECURSE decay_SOURCES src_decay/*.cpp src_decay/*.c src_decay/*.h)
file(GLOB rsrc_SOURCES rsrc/*.rc)
set_property(SOURCE ${src_SOURCES}  PROPERTY VS_SETTINGS
  $<$<CONFIG:DebugSprayed>:ExcludedFromBuild=true>
  $<$<CONFIG:ReleaseSprayed>:ExcludedFromBuild=true>)
set_property(SOURCE ${spraybuild_SOURCES} PROPERTY VS_SETTINGS
  $<$<CONFIG:Debug>:ExcludedFromBuild=true>
  $<$<CONFIG:Release>:ExcludedFromBuild=true>)

set_property(SOURCE "src/dbg.cpp" PROPERTY VS_SETTINGS
  $<$<CONFIG:Release>:ExcludedFromBuild=true>
  $<$<CONFIG:ReleaseSprayed>:ExcludedFromBuild=true>)

source_group("src_crafted" FILES ${crafted_SOURCES})
source_group("src_decay" FILES ${decay_SOURCES})
source_group("src" FILES ${src_SOURCES})
source_group(".." FILES ${_src_SOURCES})
        
## resources like lang/en_us.rc require this
set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} -I${PROJECT_SOURCE_DIR}/rsrc/")
# Include Directories, NOTE THE RC LANGUAGE IS IMPORTANT!

# fix something cmake can't on its own - must be here, not at bottom
#set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug,DebugSprayed>:Debug>$<$<CONFIG:Release,ReleaseSprayed>:DLL>")
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug,DebugSprayed>:Debug>")

add_executable (virprog WIN32
  ${_src_SOURCES} ${src_SOURCES}
  ${spraybuild_SOURCES} ${decay_SOURCES} ${crafted_SOURCES} ${rsrc_SOURCES}
)
add_custom_command(
    TARGET virprog PRE_BUILD
    COMMAND echo (Reserved message)
    #COMMAND $<$<CONFIG:DebugSprayed>:${PROJECT_SOURCE_DIR}\\$spray_prepare.bat> # now called once, not every rebuild
    #COMMAND $<$<CONFIG:ReleaseSprayed>:${PROJECT_SOURCE_DIR}\\$spray_prepare.bat>
    #COMMAND ${PROJECT_SOURCE_DIR}\\create_string_hashes.bat> # now in crypts/*bat
    #COMMAND ${PROJECT_SOURCE_DIR}\\create_string_hashes.bat>
)
add_custom_command(
    TARGET virprog POST_BUILD
    COMMAND ${PROJECT_SOURCE_DIR}\\_binhide.bat $<TARGET_FILE:virprog>
    #$<TARGET_FILE_DIR:virprog>/$<TARGET_FILE_NAME:virprog> # good stub
)
add_library(virlib SHARED
  ${_src_SOURCES} ${src_SOURCES}
  ${spraybuild_SOURCES} ${decay_SOURCES} ${crafted_SOURCES} ${rsrc_SOURCES}
)
target_compile_definitions(virlib PUBLIC _USRDLL) # obsolete, need to update
add_custom_command(
    TARGET virlib PRE_BUILD
    COMMAND echo (Reserved message)
    #COMMAND $<$<CONFIG:DebugSprayed>:${PROJECT_SOURCE_DIR}\\$spray_prepare.bat> # now called once, not every rebuild
    #COMMAND $<$<CONFIG:ReleaseSprayed>:${PROJECT_SOURCE_DIR}\\$spray_prepare.bat>
    #COMMAND ${PROJECT_SOURCE_DIR}\\create_string_hashes.bat> # now in crypts/bat
    #COMMAND ${PROJECT_SOURCE_DIR}\\create_string_hashes.bat>
)
add_custom_command(
    TARGET virlib POST_BUILD
    COMMAND ${PROJECT_SOURCE_DIR}\\_binhide.bat $<TARGET_FILE:virlib>
)

target_compile_definitions(virprog PRIVATE
  $<$<CONFIG:DebugSprayed>:SPRAYED_BUILD=1>
  $<$<CONFIG:ReleaseSprayed>:SPRAYED_BUILD=1>
  #ANTIEMU_${ANTIEMU}=1 DECRYPT_${DECRYPT}=1 SETUP_${SETUP}=1 # good stub
)
target_compile_definitions(virlib PRIVATE
  $<$<CONFIG:DebugSprayed>:SPRAYED_BUILD=1>
  $<$<CONFIG:ReleaseSprayed>:SPRAYED_BUILD=1>
  #ANTIEMU_${ANTIEMU}=1 DECRYPT_${DECRYPT}=1 SETUP_${SETUP}=1 # good stub
)

#sspi.h needs this
target_compile_definitions(virprog PRIVATE SECURITY_WIN32)
target_compile_definitions(virlib PRIVATE SECURITY_WIN32)

# fix things cmake can't fix on its own, make it default
target_compile_options(virprog PRIVATE $<$<CONFIG:DebugSprayed>:/Od /RTC1 /Ob0 /Zi>)
target_compile_options(virlib PRIVATE $<$<CONFIG:DebugSprayed>:/Od /RTC1 /Ob0 /Zi>)
target_link_options(virprog PRIVATE $<$<CONFIG:DebugSprayed>:/DEBUG> /MAP)
target_link_options(virlib PRIVATE $<$<CONFIG:DebugSprayed>:/DEBUG> /MAP)

#target_link_libraries(main)
#link_directories(main STATIC ${Boost_LIBRARY_DIRS})
#target_compile_features(main PRIVATE cxx_std_17)

set_property(TARGET virprog PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
set_property(TARGET virlib PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

