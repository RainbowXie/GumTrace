cmake_minimum_required(VERSION 3.10)

if(DEFINED ENV{IOS_TARGET})
    if(NOT DEFINED CMAKE_C_COMPILER_TARGET)
        set(CMAKE_C_COMPILER_TARGET "$ENV{IOS_TARGET}" CACHE STRING "Target triple for the C compiler")
    endif()
    if(NOT DEFINED CMAKE_CXX_COMPILER_TARGET)
        set(CMAKE_CXX_COMPILER_TARGET "$ENV{IOS_TARGET}" CACHE STRING "Target triple for the C++ compiler")
    endif()
    if(NOT DEFINED CMAKE_OBJCXX_COMPILER_TARGET)
        set(CMAKE_OBJCXX_COMPILER_TARGET "$ENV{IOS_TARGET}" CACHE STRING "Target triple for the Objective-C++ compiler")
    endif()
endif()

if(NOT DEFINED CMAKE_OSX_SYSROOT AND DEFINED ENV{IOS_SDK_PATH})
    set(CMAKE_OSX_SYSROOT "$ENV{IOS_SDK_PATH}" CACHE PATH "Path to the iPhoneOS SDK")
endif()

if(NOT DEFINED CMAKE_INSTALL_NAME_TOOL AND DEFINED ENV{OSXCROSS_INSTALL_NAME_TOOL})
    set(CMAKE_INSTALL_NAME_TOOL "$ENV{OSXCROSS_INSTALL_NAME_TOOL}" CACHE FILEPATH "Path to install_name_tool")
endif()

project(GumTrace CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/libs)
include_directories(${CMAKE_SOURCE_DIR})

set(GUMTRACE_SOURCES
        src/main.cpp
        src/GumTrace.cpp
        src/Utils.cpp
        src/CallbackContext.cpp
        src/FuncPrinter.cpp
)

add_library(GumTrace SHARED
        ${GUMTRACE_SOURCES}
)

if(ANDROID)
    message(STATUS "Configuring for Android")

    set(ANDROID_SYSROOT_INCLUDE "${CMAKE_SYSROOT}/usr/include")

    target_include_directories(GumTrace SYSTEM PUBLIC .
            ${ANDROID_SYSROOT_INCLUDE})

    target_link_libraries(GumTrace PRIVATE ${CMAKE_SOURCE_DIR}/libs/FridaGum-Android-17.8.3-fix.a)
    target_link_libraries(GumTrace PRIVATE log dl m z)

else()
    message(STATUS "Configuring for iOS")

    enable_language(OBJCXX)

    if(NOT CMAKE_OSX_SYSROOT)
        execute_process(
                COMMAND xcode-select -p
                OUTPUT_VARIABLE DEVELOPER_DIR
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET
        )
        if(DEVELOPER_DIR)
            set(CMAKE_XCODE_DEVELOPER_DIR ${DEVELOPER_DIR})
            execute_process(
                    COMMAND /usr/bin/env DEVELOPER_DIR=${DEVELOPER_DIR} xcrun --sdk iphoneos --show-sdk-path
                    OUTPUT_VARIABLE IOS_SDK_PATH
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET
            )
        else()
            execute_process(
                    COMMAND xcrun --sdk iphoneos --show-sdk-path
                    OUTPUT_VARIABLE IOS_SDK_PATH
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET
            )
        endif()
        set(CMAKE_OSX_SYSROOT ${IOS_SDK_PATH})
    else()
        set(IOS_SDK_PATH ${CMAKE_OSX_SYSROOT})
    endif()
    message(STATUS "iOS SDK Path: ${IOS_SDK_PATH}")

    set_source_files_properties(${GUMTRACE_SOURCES} PROPERTIES LANGUAGE OBJCXX)

    target_include_directories(GumTrace SYSTEM PUBLIC .)

    set_target_properties(GumTrace PROPERTIES
            LINKER_LANGUAGE OBJCXX
            OBJCXX_STANDARD 11
            OBJCXX_STANDARD_REQUIRED YES
            BUNDLE FALSE
            FRAMEWORK FALSE
            XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "NO"
            XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "NO"
            XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER ""
            MACOSX_BUNDLE FALSE
    )

    target_compile_options(GumTrace PRIVATE
            -isysroot ${IOS_SDK_PATH}
            -arch arm64
            -miphoneos-version-min=12.0
            -fvisibility=hidden
            -Wno-unused-command-line-argument
    )

    target_link_options(GumTrace PRIVATE
            -isysroot ${IOS_SDK_PATH}
            -arch arm64
            -miphoneos-version-min=12.0
    )

    target_link_libraries(GumTrace
            ${CMAKE_SOURCE_DIR}/libs/FridaGum-IOS-17.8.3-fix.a
    )

    if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(GumTrace PRIVATE
                -undefined dynamic_lookup
        )
    else()
        target_link_libraries(GumTrace
                "-framework Foundation"
                "-framework CoreFoundation"
        )
    endif()

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -ObjC++")
endif()
