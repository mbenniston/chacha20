cmake_minimum_required(VERSION 3.11)

add_library(Unity "unity.c")
target_include_directories(Unity PUBLIC ".")