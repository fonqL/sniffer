cmake_minimum_required(VERSION 3.5)

project(sniffer VERSION 0.1 LANGUAGES CXX)

add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS _WINSOCKAPI_)

if(MSVC)
    add_compile_options(/utf-8)
endif()

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Charts Sql)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Charts Sql)

file(GLOB PROJECT_SOURCES
	"src/*.cpp"
	# "src/*.h"
    "src/*.ui"
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(sniffer
	MANUAL_FINALIZATION
	${PROJECT_SOURCES}
    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET sniffer APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
	add_library(sniffer SHARED
	    ${PROJECT_SOURCES}
	)
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
	add_executable(sniffer
	    ${PROJECT_SOURCES}
	)
    endif()
endif()

target_include_directories(sniffer PRIVATE ./NpCap/Include)
target_link_directories(sniffer PRIVATE ./NpCap/Lib/x64)
target_link_libraries(sniffer PRIVATE Packet wpcap Ws2_32)

target_link_libraries(sniffer PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Charts
    Qt${QT_VERSION_MAJOR}::Sql
)

set_target_properties(sniffer PROPERTIES
    MACOSX_BUNDLE_GUI_IDENTIFIER my.example.com
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

#install(TARGETS sniffer
#    BUNDLE DESTINATION .
#    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(sniffer)
endif()
