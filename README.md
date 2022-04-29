# Set Pre-Constrained Group Signatures

_C++ implementation of the pre-constrained group signature scheme introduced in ..._

## Dependencies
This project uses the [mcl](https://github.com/herumi/mcl/) library for group arithmetic and pairings. The mcl library in turn requires [GMP](https://gmplib.org/).

## Overview
* [`lib/pcsig.h`](lib/pcsig.h): Library for set pre-constrained group signatures with functions for creating and verifying signatures.
* [`lib/linkpcsig.h`](lib/linkpcsig.h): Library for linkable set pre-constrained group signatures with functions for creating and verifying signatures.
* [`pcsig_bench.cpp`](pcsig_bench.cpp): Benchmark of the set pre-constrained group signature scheme.
* [`pcsig_bench.cpp`](pcsig_bench.cpp): Benchmark of the linkable set pre-constrained group signature scheme.

## Instructions for Benchmarking
<!-- A quick and dirty way to run the benchmark is to add [`src/gs.h`](src/gs.h) and [`src/pcsig_bench.cpp`](src/pcsig_bench.cpp) to the sample folder of the mcl library and using CMake to build mcl with the option MCL_BUILD_SAMPLE=ON. Note that you will have to modify the CMakeLists.txt file in the sample folder by adding the name of the source file [`src/pcsig_bench.cpp`](src/pcsig_bench.cpp). -->

Start by cloning the repositories.
```bash
git clone https://github.com/guruvamsi-policharla/pc-sigs
git clone https://github.com/herumi/mcl
```

Move the `pc-sigs` directory into the `mcl` directory and add the following line to the bottom of the `CMakeLists.txt` file in the `mcl` directory.

```cmake
add_subdirectory(pc-sigs)
```

<!-- Move the two files in the [`pc-sigs/src`](src) directory to the sample folder in mcl repository. -->

<!-- Add pcsig_bench to the first line of the CMakeLists.txt file in the sample folder. -->

Replace `build.sh` in the mcl directory with the `pc-sigs/build.sh`. Then execute the following command in the `mcl` directory
```bash
./build.sh
```
(You may need to make build.sh executable.)

Navigate to `build/bin` and you should find two binaries titled `pcsig_bench` and `linkpcsig_bench`.

These binary takes two parameters:

1. Number of signatures to average over.
2. Message to create the signature on.

By default the parameters are set to 100 and "hello world".

## Choosing Curves
Our implementation currently supports three curves BN254, BN381_1, BN462. To change the curve used, modify the preprocessor macro `curveid` in [`lib/pcsig.h`](lib/pcsig.h) and [`lib/linkpcsig.h`](lib/linkpcsig.h) and recompile by running `make` inside the `mcl/build` directory.

<!-- ## Benchmarks
Benchmark results in milliseconds on a 1.8 GHz Intel Core i7 Processor with 8 GB of RAM.

| Scheme      | SPC.Sign    | SPC.Verify  |  SPC.Open |
| :----:      | :----:      |    :----:   |    :----: |
| Unlinkable  | 7.7         | 32.6        | 0.05      |
| Linkable    | 1.9         | 8.8         | 0.05      |

All times in milliseconds. -->