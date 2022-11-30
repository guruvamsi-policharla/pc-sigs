# Set Pre-Constrained Group Signatures

C++ implementation of the pre-constrained group signature scheme introduced in [ePrint:2022/1643](https://eprint.iacr.org/2022/1643)

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

## Dependencies
This project uses the [mcl](https://github.com/herumi/mcl/) library for group arithmetic and pairings. The mcl library in turn requires [GMP](https://gmplib.org/).

## Overview
* [`lib/pcsig.h`](lib/pcsig.h): Library for set pre-constrained group signatures with functions for creating and verifying signatures.
* [`lib/linkpcsig.h`](lib/linkpcsig.h): Library for linkable set pre-constrained group signatures with functions for creating and verifying signatures.
* [`pcsig_bench.cpp`](pcsig_bench.cpp): Benchmark of the set pre-constrained group signature scheme.
* [`pcsig_bench.cpp`](pcsig_bench.cpp): Benchmark of the linkable set pre-constrained group signature scheme.

## Instructions for Benchmarking
Start by cloning the repositories.
```bash
git clone https://github.com/guruvamsi-policharla/pc-sigs
git clone https://github.com/herumi/mcl
```

Move the `pc-sigs` directory into the `mcl` directory and add the following line to the bottom of the `CMakeLists.txt` file in the `mcl` directory.

```cmake
add_subdirectory(pc-sigs)
```

Replace `build.sh` in the mcl directory with the `pc-sigs/build.sh`. Then execute the following command in the `mcl` directory
```bash
./build.sh
```
(You may need to make build.sh executable.)

Navigate to `build/bin` and you should find two binaries titled `pcsig_bench` and `linkpcsig_bench`.

These binaries take two parameters:

1. Number of signatures to average over.
2. Message to create the signature on.

By default the parameters are set to 100 and "hello world".

## Choosing Curves
Our implementation currently supports three curves BN254, BN381_1, BN462. To change the curve used, modify the preprocessor macro `curveid` in [`lib/pcsig.h`](lib/pcsig.h) and [`lib/linkpcsig.h`](lib/linkpcsig.h) and recompile by running `make` inside the `mcl/build` directory.

## License
This library is released under the MIT License.
