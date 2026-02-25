#!/usr/bin/env bash

bake rebuild flecs -D FLECS_SCRIPT_MATH -D FLECS_USE_OS_ALLOC
bake rebuild flecs/test/script -D FLECS_SCRIPT_MATH -D FLECS_USE_OS_ALLOC
bake run flecs/test/script -- Fuzzing -j 12

bake rebuild flecs --cfg sanitize -D FLECS_SCRIPT_MATH -D FLECS_USE_OS_ALLOC
bake rebuild flecs/test/script --cfg sanitize -D FLECS_SCRIPT_MATH -D FLECS_USE_OS_ALLOC
bake run flecs/test/script --cfg sanitize -- Fuzzing -j 12
