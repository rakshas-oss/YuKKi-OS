cmake_minimum_required(VERSION 3.18)
project(OverhauledTensorRuntime LANGUAGES CXX)

option(ENABLE_CUDA "Enable CUDA GPU runtime" ON)
option(ENABLE_TENSORRT "Enable TensorRT integration" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(ENABLE_CUDA)
    enable_language(CUDA)
    find_package(CUDA REQUIRED)
endif()

if(ENABLE_TENSORRT)
    set(TENSORRT_ROOT /usr/local/tensorrt CACHE PATH "Path to TensorRT root")
    find_path(TENSORRT_INCLUDE_DIR NvInfer.h HINTS ${TENSORRT_ROOT}/include /usr/include /usr/local/cuda/include)
    find_library(NVINFER_LIB nvinfer HINTS ${TENSORRT_ROOT}/lib /usr/lib/x86_64-linux-gnu /usr/local/cuda/lib64)
    find_library(NVONNXPARSER_LIB nvonnxparser HINTS ${TENSORRT_ROOT}/lib /usr/lib/x86_64-linux-gnu /usr/local/cuda/lib64)

    if(NOT TENSORRT_INCLUDE_DIR OR NOT NVINFER_LIB OR NOT NVONNXPARSER_LIB)
        message(FATAL_ERROR "TensorRT requested but not found. Set ENABLE_TENSORRT=OFF or install TensorRT.")
    endif()
endif()

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_library(nvlink_placement
    src/nvlink_placement.cpp
)

target_include_directories(nvlink_placement
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(ENABLE_CUDA)
    target_compile_definitions(nvlink_placement PUBLIC NVLINK_PLACEMENT_HAS_CUDA=1)
    target_link_libraries(nvlink_placement PRIVATE cuda cudart)
endif()

if(ENABLE_CUDA)
    add_executable(gpu_runtime_server src/gpu_runtime_server.cpp)
    target_include_directories(gpu_runtime_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(gpu_runtime_server PRIVATE nvlink_placement)

    if(ENABLE_TENSORRT)
        target_include_directories(gpu_runtime_server PRIVATE ${TENSORRT_INCLUDE_DIR})
        target_link_libraries(gpu_runtime_server PRIVATE ${NVINFER_LIB} ${NVONNXPARSER_LIB} cuda cudart pthread)
        target_compile_definitions(gpu_runtime_server PRIVATE NVLINK_ADI_HAS_CUBLAS=1)
    endif()
endif()

install(TARGETS nvlink_placement DESTINATION lib)
if(ENABLE_CUDA)
    install(TARGETS gpu_runtime_server DESTINATION bin)
endif()
