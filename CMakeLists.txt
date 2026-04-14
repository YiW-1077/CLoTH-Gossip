cmake_minimum_required(VERSION 3.22)
project(CLoTH_Gossip C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

file(COPY config/cloth_input.txt DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY config/data/channels_ln.csv DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY config/data/edges_ln.csv DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY config/data/nodes_ln.csv DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY run-simulation.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY scripts/analyze_output.py DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/scripts)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/result)

# Core Simulation Engine
set(CORE_SOURCES
    src/core/cloth.c
    src/core/event.c
    src/core/payments.c
)

# Network Model & Routing
set(NETWORK_SOURCES
    src/network/network.c
    src/network/routing.c
)

# HTLC & Payment Mechanics
set(SIMULATION_SOURCES
    src/simulation/htlc.c
)

# Data Structures & Utilities
set(DATA_STRUCTURES_SOURCES
    src/data_structures/array.c
    src/data_structures/heap.c
    src/data_structures/list.c
    src/data_structures/utils.c
)

add_executable(${PROJECT_NAME}
    # Headers
    include/core/cloth.h
    include/core/event.h
    include/core/payments.h
    include/network/network.h
    include/network/routing.h
    include/simulation/htlc.h
    include/data_structures/array.h
    include/data_structures/heap.h
    include/data_structures/list.h
    include/data_structures/utils.h
    # Source files
    ${CORE_SOURCES}
    ${NETWORK_SOURCES}
    ${SIMULATION_SOURCES}
    ${DATA_STRUCTURES_SOURCES}
)

find_package(GSL REQUIRED)
target_link_libraries(${PROJECT_NAME} GSL::gsl GSL::gslcblas m)
