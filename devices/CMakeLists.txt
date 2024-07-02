# Minimum required CMake version
cmake_minimum_required(VERSION 3.20)

# Add all devices subdirectories
add_subdirectory(tplink-plug)
add_subdirectory(xiaomi-cam)
add_subdirectory(dlink-cam)
add_subdirectory(philips-hue)
add_subdirectory(smartthings-hub)
add_subdirectory(amazon-echo)
add_subdirectory(example)