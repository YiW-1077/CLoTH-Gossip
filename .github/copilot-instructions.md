# Copilot instructions for CLoTH-Gossip

CLoTH-Gossip is a C-based discrete-event simulator for Lightning Network–style payment-channel routing + HTLC mechanics. Most “how do I run this?” knowledge lives in `README.md` plus the shell scripts in the repo root.

## Build / run / (smoke) checks

### Build (CMake; produces `CLoTH_Gossip`)
```sh
mkdir -p cmake-build-debug
cd cmake-build-debug
cmake ..
make
```

CMake copies runtime inputs into the build dir (see `CMakeLists.txt`): `cloth_input.txt`, `*_ln.csv`, and `run-simulation.sh`.

### Run the simulator directly (fastest for local iteration)
Run from the build directory so `cloth_input.txt` + CSVs are found in the current working directory.

```sh
cd cmake-build-debug
mkdir -p result
GSL_RNG_SEED=42 ./CLoTH_Gossip ./result/
```

Important: the output directory argument is concatenated with filenames in `src/cloth.c`, so pass a path ending with `/` (the scripts do this).

### Run via wrapper (reproducible runs into an output folder)
`run-simulation.sh` creates a temporary “environment” copy of the repo via `rsync`, rewrites `cloth_input.txt` via `sed`, builds inside that copy (`cmake . && make`), runs `./CLoTH_Gossip <output_dir/>`, then deletes the environment.

Example (must provide at least one `key=value` after the output dir):
```sh
mkdir -p /tmp/cloth-out
./run-simulation.sh 42 /tmp/cloth-out n_payments=200 mpp=0 routing_method=cloth_original
```

Notes:
- The script currently requires **at least 3 args** (`$# -lt 3`), even though it treats args 3..N as settings.
- It writes build/run logs under `<output_dir>/log/` and a `progress.tmp` file used by batch runners.

### Makefile (single-command gcc build; produces `cloth`)
```sh
make build
```
This compiles all `src/*.c` into a single executable and links GSL (`-lgsl -lgslcblas -lm`).

### Tests / lint
There is no unit-test or lint target wired up (no `ctest`, no `make test`, no formatter config). Treat a small simulation run as the “smoke test”.

## High-level architecture (big picture)

### Runtime flow (discrete-event simulation)
- Entry point: `src/cloth.c:main`.
- Reads configuration from `cloth_input.txt` via `read_input()`.
- Initializes:
  - `struct network* network = initialize_network(...)` (`src/network.c`)
  - `struct array* payments = initialize_payments(...)` (`src/payments.c`)
  - `simulation->events = initialize_events(payments)` (`src/event.c`) — one initial `FINDPATH` event per payment
- Precomputes initial routes in parallel:
  - `initialize_dijkstra(...)` + `run_dijkstra_threads(...)` (`src/routing.c`, `N_THREADS=8`)
  - Results cached in the global `paths[payment_id]` used on the first attempt.
- Core loop: pop next event from a min-heap, advance `simulation->current_time`, and dispatch by `event->type`.
  - Event handlers live in `src/htlc.c` (payment lifecycle) and `src/network.c` (channel open / group updates).
- Writes CSV outputs via `write_output()` (`src/cloth.c`) at the end.

### Key modules (where to look)
- `src/network.c` / `include/network.h`
  - Graph model: nodes, channels, directed edges, policies.
  - Builds network either from CSV files (`generate_network_from_files`) or randomly (scale-free augmentation of LN snapshot).
  - Group routing data model: `struct group`, `update_group()`, and history tracking (`struct group_update`).
- `src/routing.c` / `include/routing.h`
  - Dijkstra-like path finding modeled after lnd (see comments at top of file).
  - Supports multiple `routing_method` variants (see `include/cloth.h`).
- `src/htlc.c` / `include/htlc.h`
  - HTLC forwarding simulation and retry behavior.
  - Enforces balance + policy constraints per hop; updates mission-control style success/fail memory (`node_pair_result`).
  - Optional MPP support: payments can be split into 2 shards and post-processed.
- `src/event.c` / `include/event.h`
  - Event struct + heap ordering by event time.
- Data-structure helpers: `src/{heap,array,list}.c` used throughout.

### Batch experiments / analysis
- `run_all_simulations_change_*.sh` enqueue many `run-simulation.sh` runs concurrently and show progress by reading `progress.tmp`.
- `scripts/analyze_output.py` walks an output root and processes each simulation directory (identified by presence of `cloth_input.txt`), producing `summary.csv` and optional plots.

## Key repo-specific conventions

### Units (this repo mixes “msat” and “sat” by input source)
- Network and payments **CSV templates** explicitly use **millisatoshi**:
  - `channels_template.csv`: `capacity(millisat)`
  - `edges_template.csv`: balances/fees/min_htlc in `millisat`
  - `payments_template.csv`: `amount(millisat)` (but see note below)
- `cloth_input.txt` payment amount + fee limit parameters are treated as **satoshis** in code and converted to msat by multiplying by 1000:
  - `average_payment_amount`, `variance_payment_amount` → `payments.c` multiplies by 1000
  - `average_max_fee_limit`, `variance_max_fee_limit` → `payments.c` multiplies by 1000

### `cloth_input.txt` parsing is strict
- No spaces around `=` are allowed (hard error in `read_input()` in `src/cloth.c`).
- Some parameters intentionally allow an empty value; in `read_input()` these map to sentinel values:
  - `group_size`, `group_limit_rate`, `cul_threshold_dist_alpha/beta`: empty string becomes `-1`
  - Many other numeric fields use `strtol/strtod` directly; empty strings become `0`.

### Routing methods & required group parameters
`routing_method` in `cloth_input.txt` is a string mapped to `enum routing_method` in `include/cloth.h`:
- `cloth_original`, `channel_update`, `ideal`, `group_routing`, `group_routing_cul`

When `routing_method=group_routing`:
- `group_size` must be set (>= 0)
- `group_limit_rate` must be in `[0,1]`
- `group_cap_update` must be explicitly `true` or `false` (validated)

When `routing_method` is `group_routing` or `group_routing_cul`:
- Groups are constructed at initialization in `main` (before payments/events) and can be updated via `UPDATEGROUP` / `CONSTRUCTGROUPS` events.

### Output directory path must end with `/`
`src/cloth.c` builds output paths via string concatenation (`strcpy(output_filename, output_dir_name); strcat(output_filename, "payments_output.csv")`). Pass `./some_dir/` (trailing slash) to avoid filenames like `some_dirpayments_output.csv`.

### Payment CSV from file expects a max_fee_limit column
`payments.c:generate_payments()` parses 6 columns:
`id,sender,receiver,amount,start_time,max_fee_limit`.
The current `payments_template.csv` header does not include `max_fee_limit`; if you run with `generate_payments_from_file=true`, ensure your CSV matches what the parser expects.

### Shell scripts assume GNU-ish userland
The batch scripts use `wait -n`, `bc`, and rely on `sed -i -e ...` in `run-simulation.sh`. If running on macOS, you may need a newer bash and GNU sed (or adjust the script) for the wrappers to work as-is.
