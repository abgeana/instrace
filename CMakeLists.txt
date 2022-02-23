cmake_minimum_required(VERSION 3.7)

project(instrace)

set(DynamoRIO_DIR /home/abg/projects/ybn/DynamoRIO-Linux-9.0.1/cmake)
find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO package required to build")
endif ()

set(SRC
    src/instrace.c
    src/utils.c
)
add_library(instrace SHARED ${SRC})

configure_DynamoRIO_client(instrace)
use_DynamoRIO_extension(instrace drmgr)
use_DynamoRIO_extension(instrace drreg)
use_DynamoRIO_extension(instrace drx)
