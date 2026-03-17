# Nudge: A Private Recommendations Engine

> Nudge is a recommender system with cryptographic privacy. A Nudge deployment consists of three infrastructure servers and many users, who retrieve/rate items from a large data set (e.g., videos, posts, businesses). Periodically, the Nudge servers collect ratings from users in secret-shared form, then run a three-party computation to train a lightweight recommender model on users' private ratings. Finally, the servers deliver personalized recommendations to each user. At every step, Nudge reveals nothing to the servers about any user's preferences beyond the aggregate model itself. User privacy holds against an adversary that compromises the entire secret state of one server. The technical core of Nudge is a new, three-party protocol for matrix factorization. On the Netflix data set with half a million users and ten thousand items, Nudge (running on three 192-core servers on a local-area network) privately learns a recommender model in 50 mins with 40 GB of server-to-server communication. On a standard quality benchmark (nDCG@20), Nudge scores 0.29 out of 1.0, on par with non-private matrix factorization and just shy of non-private neural recommenders, which score 0.31.

This repository contains the code for the paper [Nudge: A Private Recommendations Engine](https://eprint.iacr.org/2026/179.pdf) by Alexandra Henzinger, Emma Dauterman, Henry Corrigan-Gibbs, and Dan Boneh (USENIX Security 2026).

**Warning**: This code is a research prototype.

## Overview

Nudge is a system for privacy-preserving recommendations built on 3-party secure multi-party computation (MPC). Three servers jointly compute on secret-shared user data, so that no single server ever sees any user's ratings. The system uses **replicated secret sharing (RSS)**: each secret value is split into three shares such that any two reconstruct the original, but no single share reveals anything.

Nudge operates in three phases:

1. **Data collection**. Each user secret-shares their private rating vector across the three servers using a **multiplicative distributed point function (DPF)**, which directly produces replicated secret shares of the rating matrix. The servers verify that all ratings lie in {0,1} by exchanging only O(λ) bits, regardless of the number of users or items.

2. **Private matrix factorization**. The three servers jointly run a **power-iteration** protocol on their RSS shares of the user-item matrix U to factor U ≈ A·B. Each iteration alternates between (a) non-interactive matrix-vector products on secret-shared data and (b) secret-shared non-linear operations (truncation and normalization) built on **function secret sharing**. User embeddings A remain secret-shared; item embeddings B are revealed in cleartext. Communication between servers scales as O(m + n) (not O(mn)), where m is the number of users and n is the number of items.

3. **Recommendation serving**. For each user, the servers compute RSS shares of that user's recommendation scores a(i)·B and forward them to the user, who reconstructs the top-ranked items locally. This requires O(n) bits of user-server communication per query.

### Codebase 

This repository contains the following directories:

**Application layer:**
- `main.go` — CLI entry point: launches servers, clients, and benchmarks for all three phases
- `protocol/` — High-level 3-party protocol: server and client functionality for all three phases 
- `share/` — additive/RSS secret-sharing primitives and matrix operations (matrix multiply, transpose). Heavy on CGo: `matrix.c` implements SIMD-accelerated matrix arithmetic over secret shares
- `net/` — Multi-threaded network messaging between the three servers

**Cryptographic primitives:**
- `dcf/` — Distributed Comparison Function: two-party keys encoding f(x) = [x >= alpha], used to implement fixed-point truncation and normalization. Three output widths: 64-bit, 128-bit, and small-output 128-bit 
- `dmsb/` — Distributed Most-Significant-Bit: built on top of `dcf/`, produces a one-hot vector indicating the MSB position of a secret value. Used in the normalization protocol to find a starting point for Newton-Raphson iteration
- `multdpf/` — Multiplicative DPF: a DPF whose output is in RSS form (replicated secret shares rather than plain additive shares), used for data collection
- `rand/` — AES-CTR buffered PRG pool

**Low-level acceleration:**
- `aes/` — AMD64 assembly (`aes_amd.s`) for AES-128; used as the PRF throughout the codebase
- `uint128/` — 128-bit integer arithmetic via CGo (`uint128.c`); wraps GCC `__int128` with SIMD flags (`-O3 -march=native -maes -mavx2`). This package is dot-imported throughout the codebase

### Concrete parameters

Nudge uses the ring Z_{2^128} (bit length b = 128) and AES-128 as a PRF (seed length λ = 128). The number of bits of fractional bits of fixed-point precision, and the number of iterations of Newton-Raphson approximation, are hyperparameters set in the JSON configuration files in `params/`.

### CGo dependencies

Three packages use CGo and require a C compiler with AVX2/AES-NI support:
- `uint128/` — `uint128.c` / `uint128.h` with `C.Elem128` type
- `share/` — `matrix.c` / `matrix.h` for matrix operations on secret shares
- `aes/` — assembly only (no C), but linked via `go:linkname`

## Setup

### Requirements

To run Nudge, install:
- [Go](https://go.dev/) 1.22 or later
- A C compiler (GCC recommended) with support for AVX2 and AES-NI instructions (Intel Haswell / AMD Ryzen and later). These are used as a performance optimization; the code will still compile without them at reduced performance.
- For experiments using the MovieLens 1M or Netflix datasets, AWS credentials must be configured to load matrix shares from S3. Alternatively, each dataset can be fetched from Kaggle 

### Build

Run: 

```bash
go build ./...
```

### Run tests

Run the full test suite:

```bash
go test ./...
```

Run tests for a specific package:

```bash
go test -v ./dcf
go test -v ./share
go test -v ./dmsb
go test -v ./multdpf
go test -v ./protocol
```

Run a single test:

```bash
go test -v ./dcf -run TestEval64
go test -v ./share -run TestAdditive128
```

Run benchmarks:

```bash
go test -v ./dcf -bench BenchmarkGen64 -benchtime=1s
```

**Note:** `TestPowerIt` in `share/` is flaky — the randomized power-iteration test occasionally fails on a sparse random-matrix test case. Re-run before investigating. `TestS3` in `share/` requires AWS credentials.

## Usage

All three Nudge servers must be started (in separate terminals or on separate machines) before any of them will proceed. In a local setup, use `127.0.0.1` for all server IP addresses.

### Phase 1: Data Collection

The data-collection servers accept secret-shared ratings from clients:

```bash
# Three servers (separate terminals)
go run . data-server 0 <nusers> <nitems>
go run . data-server 1 <nusers> <nitems>
go run . data-server 2 <nusers> <nitems>

# Client: connect and submit ratings
go run . data-client <nusers> <nitems> <ip0> <ip1> <ip2>

# Benchmark: measure latency and throughput of data collection
go run . data-bench <nusers> <nitems> <ip0> <ip1> <ip2>
```

### Phase 2: Matrix Factorization

Launch three servers with a secret-shared matrix. The matrix can come from a local CSV file, from S3, or be generated randomly:

```bash
# From local files
go run . server 0 <ip0> <ip1> <ip2> share/test_matrix/small_share0.csv
go run . server 1 <ip0> <ip1> <ip2> share/test_matrix/small_share1.csv
go run . server 2 <ip0> <ip1> <ip2> share/test_matrix/small_share2.csv

# From a random matrix with custom dimensions
go run . server 0 <ip0> <ip1> <ip2> --random --users <m> --items <n>
go run . server 1 <ip0> <ip1> <ip2> --random --users <m> --items <n>
go run . server 2 <ip0> <ip1> <ip2> --random --users <m> --items <n>
```

Power-iteration hyperparameters are set via `--params` (default: `params/tiny_params.json`) or overridden by dataset flags:

| Params file                         | K (embedding dim) | Intended for                          |
|-------------------------------------|-------------------|---------------------------------------|
| `params/tiny_params.json`           | 2                 | Local testing (default)               |
| `params/small_params.json`          | 10                | Small experiments                     |
| `params/movielens_tiny_params.json` | 8                 | MovieLens 100K / Tiny                 |
| `params/movielens_params.json`      | 10                | MovieLens 1M                          |
| `params/cheap_params.json`          | 2                 | Cheap Netflix experiment reproduction |
| `params/full_params.json`           | 50                | Netflix                               |

### Phase 3: Recommendation Serving

After training, the servers can serve personalized recommendations to clients:

```bash
# Three servers (separate terminals)
go run . recs-server 0 <nusers> <nclusters> <nitemsPerCluster>
go run . recs-server 1 <nusers> <nclusters> <nitemsPerCluster>
go run . recs-server 2 <nusers> <nclusters> <nitemsPerCluster>

# Client: fetch recommendations
go run . recs-client <nusers> <nitems> <ip0> <ip1> <ip2>

# Benchmark: measure latency and throughput
go run . recs-bench <nusers> <nclusters> <nitemsPerCluster> <ip0> <ip1> <ip2>
```

For a dataset with n items total and no clustering, set `nclusters=1` and `nitemsPerCluster=n`.

## Reproducing paper experiments

This section gives commands to reproduce the performance results from the paper. All commands use `d=2` (embedding dimension K=2 via `params/cheap_params.json`) for cheaper verification runs. The paper's reported numbers use the dataset-specific K values shown in the params table above; to reproduce at full scale, substitute the appropriate params file.

Each `server` command must be run three times (once per server) on separate machines. (If instead running on a local setup, replace all IPs with `127.0.0.1`.) The paper's LAN and WAN experiments use three separate AWS machines; to reproduce the paper's exact runtimes, use `r7a.48xlarge` instances (192 cores, 1536 GB RAM) for the large datasets and `r7a.large` (2 cores, 16 GB RAM) or `r7a.4xlarge` (16 cores, 128 GB RAM) for MovieLens.

### Table 6: Private matrix factorization

Each command below is run once per server (with `{0,1,2}` replaced by the server's ID). The system outputs wall-clock time and server-to-server communication upon completion.

**MovieLens Tiny** (940 users x 40 items, K=8 in paper):

```bash
go run . server {0,1,2} <ip0> <ip1> <ip2> --movielensTiny
```

**MovieLens 100K** (943 users x 1,682 items, K=8 in paper):

```bash
go run . server {0,1,2} <ip0> <ip1> <ip2> --movielens100K
```

**MovieLens 1M** (6,040 users x 3,883 items, K=10 in paper):

```bash
go run . server {0,1,2} <ip0> <ip1> <ip2> --movielens
```

**Netflix** (463,435 users x 17,769 items, K=50 in paper) — set up to require matrix shares on S3:

```bash
go run . server {0,1,2} <ip0> <ip1> <ip2> --netflix
```

### Figure 7: Scaling to larger datasets

The following commands measure Nudge's runtime and communication on matrices matching the dimensions of public recommendation datasets. All use `--random` to generate a random matrix of the given size, avoiding the need to download data. To run cheaply with K=2, first edit `params/full_params.json` to set `"K": 2` (or replace it with `params/cheap_params.json` in the source code at line 267 of `main.go`).

**Pinterest** (55,187 users x 9,916 items):

```bash
go run . server {0,1,2} <ip0> <ip1> <ip2> --random --users 55187 --items 9916
```

**Netflix** (463,435 users x 17,769 items):

```bash
go run . server {0,1,2} <ip0> <ip1> <ip2> --random --users 463435 --items 17769
```

**Criteo** (6,040,000 users x 700 items):

```bash
go run . server {0,1,2} <ip0> <ip1> <ip2> --random --users 6040000 --items 700
```

**Steam** (2,567,538 users x 15,474 items):

```bash
go run . server {0,1,2} <ip0> <ip1> <ip2> --random --users 2567538 --items 15474
```

**Microsoft News** (50,000 users x 160,000 items):

```bash
go run . server {0,1,2} <ip0> <ip1> <ip2> --random --users 50000 --items 160000
```

**Yelp** (279,000 users x 148,000 items):

```bash
go run . server {0,1,2} <ip0> <ip1> <ip2> --random --users 279000 --items 148000
```

### Table 8: End-to-end performance (data collection and recommendation serving)

These benchmarks measure data-collection throughput/latency and recommendation-serving throughput/latency. The paper reports numbers on the Netflix dataset dimensions. Each benchmark requires three servers running in separate terminals, plus a client.

**Data-collection benchmark** (Netflix dimensions):

```bash
# Three servers
go run . data-server 0 463435 17769
go run . data-server 1 463435 17769
go run . data-server 2 463435 17769

# Benchmark client (separate terminal, after all servers are running)
go run . data-bench 463435 17769 <ip0> <ip1> <ip2>
```

**Recommendation-serving benchmark** (Netflix dimensions):

```bash
# Three servers
go run . recs-server 0 463435 1 17769
go run . recs-server 1 463435 1 17769
go run . recs-server 2 463435 1 17769

# Benchmark client (separate terminal, after all servers are running)
go run . recs-bench 463435 1 17769 <ip0> <ip1> <ip2>
```

## Citation

```bibtex
@inproceedings{nudge,
  author    = {Alexandra Henzinger and Emma Dauterman and Henry Corrigan-Gibbs and Dan Boneh},
  title     = {Nudge: A Private Recommendations Engine},
  booktitle = {USENIX Security},
  year      = {2026},
}
```
