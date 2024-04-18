#!/bin/bash

# Build the project.
# Usage: build.sh [-d working_directory] [-t cmake_toolchain_file]
#   -d working_directory: The directory to build the project in.
#   -t cmake_toolchain_file: The CMake toolchain file to use.

# Default values
WORKING_DIRECTORY=""
CMAKE_TOOLCHAIN_FILE=""

# Print usage information
usage() {
    echo "Usage: $0 [-d working_directory] [-t cmake_toolchain_file]" 1>&2
    exit 1
}

# Parse command line arguments
while getopts "d:t:" opt;
do
    case "${opt}" in
        d)
            # Working directory
            WORKING_DIRECTORY="${OPTARG}"
            echo "Building in directory ${WORKING_DIRECTORY}"
            ;;
        t)
            # CMake toolchain file
            CMAKE_TOOLCHAIN_FILE="${OPTARG}"
            echo "Using CMake toolchain file ${CMAKE_TOOLCHAIN_FILE}"
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

# Change to working directory if specified
if [[ $WORKING_DIRECTORY ]]
then
    cd $WORKING_DIRECTORY
fi

# Clean directory
rm -rf build bin

# Build project
mkdir build bin
cd build
if [[ $CMAKE_TOOLCHAIN_FILE ]]
then
    cmake -DCMAKE_TOOLCHAIN_FILE=$CMAKE_TOOLCHAIN_FILE ..
else
    cmake ..
fi
cmake --build .
