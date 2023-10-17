cmake_minimum_required (VERSION 3.5.1)

# set(CMAKE_C_COMPILER "/usr/bin/clang-11")
# set(CMAKE_CXX_COMPILER "/usr/bin/clang++-11")


### To use gcc/g++ on a Macintosh, you must set the Compilers
### here, not inside the project
##if(APPLE)
##       set(CMAKE_C_COMPILER "/usr/local/bin/gcc-7")
##       set(CMAKE_CXX_COMPILER "/usr/local/bin/g++-7")
##endif()
### TODO: for now, we use CLang for Mac
###
### In order to create OpenFHE's static libraries you should enable
### the BUILD_STATIC option. For that, you run "cmake .. -DBUILD_STATIC=ON".
### After having your link completed you will find static libs
### with the suffix "_static" in ./build/libs/.
### Examples: OPENFHEpke_static.a, OPENFHEcore_static.a, etc.
### After you run "make install" in your build directory, you can build your custom application.
### If you need your application to be linked statically, then run "cmake .. -DBUILD_STATIC=ON"

project(demo CXX)
set(CMAKE_CXX_STANDARD 17)


option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package(OpenFHE)

set( CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS} )

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
### add directories for other OpenFHE modules as needed for your project

link_directories( ${OpenFHE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
if(BUILD_STATIC)
    set( CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
    link_libraries( ${OpenFHE_STATIC_LIBRARIES} )
else()
    set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS} )
    link_libraries( ${OpenFHE_SHARED_LIBRARIES} )
endif()

### ADD YOUR EXECUTABLE(s) HERE
### add_executable( EXECUTABLE-NAME SOURCES )
###
### EXAMPLE:
### add_executable( test demo-simple-example.cpp )



# Ensure we have pthreads
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)


file(GLOB SOURCES "src/*.cpp")
file(GLOB HEADERS "include/*.hpp")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# List the source files
set(SOURCESMFBR ${SOURCES} ${HEADERS})




# MFBR v2.0

add_executable( expMFIPv2Verification expMFIPv2Verification.cpp ${SOURCESMFBR})



# ======= Updated for OpenFHE ========

# MFBR v1.0

add_executable( expMFIPv1Verification expMFIPv1Verification.cpp ${SOURCESMFBR}) 

# Baseline IP 

add_executable( expIPBaselineVerification expIPBaselineVerification.cpp ${SOURCESMFBR})

# Boddeti
add_executable( expIPBoddetiVerification expIPBoddetiVerification.cpp ${SOURCESMFBR}) 

