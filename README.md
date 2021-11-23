# Set Pre-Constrained Group Signatures

_C++ implementation of the pre-constrained group signature scheme introduced in ..._

## Dependencies
This project uses the [mcl](https://github.com/herumi/mcl/) library for group arithmetic and pairings.

## Overview
* [`src/gs.h`](src/gs.h): Library for pre-constrained group signatures with functions for creating and verifying signatures.
* [`src/pcsig_bench.cpp`](src/pcsig_bench.cpp): Benchmark of the set pre-constrained group signature scheme.

## Build
A quick and dirty way to run the benchmark is to add [`src/gs.h`](src/gs.h) and [`src/pcsig_bench.cpp`](src/pcsig_bench.cpp) to the sample folder of the mcl library and using CMake to build mcl with the option MCL_BUILD_SAMPLE=ON. Note that you will have to modify the CMakeLists.txt file in the sample folder by adding the name of the source file [`src/pcsig_bench.cpp`](src/pcsig_bench.cpp).

The binary takes two parameters

1. Number of signatures to average over.
2. Message to create the signature on.

By default the parameters are set to 100 and "hello world".

## Benchmarks
Benchmark results on a 1.8 GHz Intel Core i7 Processor with 8 GB of RAM.

| Scheme      | SPC.Sign    | SPC.Verify  |  SPC.Open |
| :----:      | :----:      |    :----:   |    :----: |
| Unlinkable  | 7.7 (ms)    | 32.6 (ms)   | 0.05 (ms) |
| Linkable    | 1.9 (ms)    | 8.8 (ms)    | 0.05 (ms) |


