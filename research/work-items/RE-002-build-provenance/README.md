# RE-002: What build configuration produced hl-node #94, #115 and the visor?

- Component ID: build provenance (no catalogue component)
- Target releases and full SHA-256:
  - `artifacts/node/94/hl-node` `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91774280 bytes)
  - `artifacts/node/115/hl-node` `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105896032 bytes)
  - `artifacts/visor/captured/hl-visor` `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31` (8305392 bytes)
- Source commit: upstream `main` at `6fb8631`. No reference source was used.
- Claim status: observation for every `exact` fact, inference for every `inferred` fact, unresolved for every `unknown` fact.
- Scope included: ELF headers, program headers, `.dynamic`, `.dynstr`, `.comment`, and path strings in the three
  targets, plus the source of the one git dependency and a version bound for each #94 path override.
- Scope excluded: disassembly, execution of any target, and rebuilding hl-node. No Hyperliquid source is available, so no build was attempted.

## Reproduce

Run these commands from the repository root after `make pull` (or an LFS fetch) on Linux with Python 3.

```sh
make verify                                   # hashes and signatures of the targets
make provenance                               # writes provenance-{94,115,visor}.json here
python3 tools/build_provenance.py --check     # exits 1 if a committed record is stale
python3 tools/build_provenance.py --diff 94 115
make path-origin                              # writes sourcing-{94,115}.json here
make fork-id                                  # re-derives the reth checkout suffix from the URL candidates
make override-versions                        # writes override-versions-94.json here
```

`tools/build_provenance.py` refuses a target whose SHA-256 or size differs from `provenance/artifacts.json`. It reads the file and never runs it. One run over all three targets takes about 2 seconds.

Each record lists facts with one of three labels:

| Label | Meaning | Carries |
| --- | --- | --- |
| `exact` | Bytes present in the target | File offset, section, and occurrence count |
| `inferred` | A conclusion drawn from `exact` facts | The reasoning |
| `unknown` | Not recoverable from these bytes | What evidence would resolve it |

Fact counts per record:

| Target | exact | inferred | unknown |
| --- | ---: | ---: | ---: |
| node #94 | 156 | 7 | 9 |
| node #115 | 171 | 7 | 9 |
| visor | 99 | 6 | 10 |

Most `exact` facts are dependency paths: 118 registry crates in #94, 131 vendored directories in #115, and 65 vendored directories in the visor.

## Evidence

### Toolchain stamps (exact)

| Field | #94 | #115 and visor |
| --- | --- | --- |
| `.comment` rustc | `rustc version 1.94.1 (e408947bf 2026-03-25)` | `rustc version 1.95.0 (59807616e 2026-04-14)` |
| `.comment` linker | `LLD 21.1.8 (... 00d23d10dc48...)` | `LLD 22.1.2 (... 1cb4e3833c19...)` |
| `.comment` clang | `21.1.0-rc2` | `22.1.0-rc2` |
| `.comment` GCC | `Ubuntu 13.3.0-6ubuntu2~24.04.1` | same |
| `/rustc/<commit>/` paths | `e408947bfd200af42db322daf0fadfe7e26d3bd1`, 109 times | `59807616e1fa2540724bfbac14d7976d7e4a3860`, 110 times in #115, 93 in the visor |
| Source root | `/home/ubuntu/hl/code_Mainnet` | same |
| jemalloc | `5.3.0-1-ge13ca993e8ccb9ba9847cc330696e02839f328f7` | same |
| Build ID | `29a7b9d6c31d0c687c376a834eba4f3ddaac660b` | #115 `ac2880fc...`, visor `b55c82cd...` |

The `/rustc/` path commits match `rustc -vV` from the official 1.94.1 and 1.95.0 toolchains. Those toolchains report LLVM 21.1.8 and LLVM 22.1.2, the same versions as the LLD stamps.

The visor carries the same rustc, LLD, and clang stamps as node #115.

### Hardening and linkage (exact, identical in all three)

- `ET_DYN` with `DF_1_PIE`, `DF_BIND_NOW`, a read-only `PT_GNU_RELRO`, and a non-executable `PT_GNU_STACK` (`RW`).
- No `RUNPATH` or `RPATH`. No `.symtab`, no `.debug*` sections, and no `.note.gnu.property`.
- `DT_NEEDED` for the node: `libstdc++.so.6 libssl.so.3 libcrypto.so.3 libgcc_s.so.1 libm.so.6 libc.so.6 ld-linux-x86-64.so.2`. The visor has the same list without `libstdc++.so.6`.
- Highest symbol versions for the node: `GLIBC_2.39`, `GLIBCXX_3.4.30`, `CXXABI_1.3.11`, `GCC_4.2.0`, `OPENSSL_3.0.0`.
- The node imports eight `_FORTIFY_SOURCE` helpers, such as `__memcpy_chk` and `__snprintf_chk`, plus `__stack_chk_fail`. The visor imports only `__stack_chk_fail`.

### Dependency layout changed between #94 and #115

Node #94 built from a Cargo home. Node #115 built from a vendored tree.

| | #94 | #115 |
| --- | --- | --- |
| crates.io crates | `/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/<name>-<version>/`, 809 path occurrences, 118 name-version pairs over 114 names | none |
| Vendored crates | none | `/home/ubuntu/hl/code_Mainnet/z_vendor/<dir>/`, 863 occurrences, 131 directories, 18 with a version in the name |
| Git dependency | `/home/ubuntu/.cargo/git/checkouts/reth-e231042ee7db3fb7/3212af2/`, 10 occurrences | none |
| Patched forks | `/home/ubuntu/hl/{hyper-fork, hyper-tls-fork, bincode-fork, hyper-alloy-core-fork}` | `code_Mainnet/z_forks/{hyper-fork, hyper-tls-fork, bincode-fork, reth-chainspec, reth-ethereum-forks, reth-rpc-eth-types, reth-rpc-server-types, revm-precompile}` |
| std dependencies | `rustc-demangle 0.1.26` | `rustc-demangle 0.1.27` |

Only `rustc-demangle` differs among the std dependencies, and it changes with the rustc upgrade.

#94 has 4 crates at two versions each: `foldhash 0.1.4/0.2.0`, `hashbrown 0.14.5/0.16.1`, `sha2 0.9.9/0.10.8`, and `socket2 0.4.10/0.5.7`.

Matching #94 crate names against #115 directory names (version suffix removed) gives 104 shared names, 10 names only in #94, and 20 only in #115:

- Only in #94: `c-kzg ecdsa revm revm-precompile revm-primitives rustc-hash ryu substrate-bn tokio-metrics wyz`.
- Only in #115: `alloy-evm alloy-primitives alloy-rpc-types-eth alloy-sol-types ark-bn254 ark-ec ark-ff base64 itertools keccak-asm memchr nybbles revm-bytecode revm-context revm-context-interface revm-handler revm-inspector revm-state serde_core zmij`.

Selected #94 versions (exact, from registry paths): `revm 19.2.0`, `revm-interpreter 15.0.0`, `revm-precompile 16.0.0`, `revm-primitives 15.1.0`, `alloy-consensus 0.9.2`, `alloy-eips 0.9.2`, `alloy-trie 0.7.8`, `tokio 1.44.2`, `hyper 0.14.29`, `axum 0.6.20`, `openssl 0.10.72`, `openssl-sys 0.9.107`, `serde 1.0.217`, `serde_json 1.0.120`, `k256 0.13.3`, `secp256k1 0.29.0`, `blst 0.3.13`, `c-kzg 1.0.3`. The full list is in `provenance-94.json` under `crate.registry`.

### Fork matrix

| Fork | #94 | #115 | visor | Base version |
| --- | --- | --- | --- | --- |
| hyper-fork | local path, 198 occ. | `z_forks`, 200 occ. | `z_forks` | unknown |
| hyper-tls-fork | local path | `z_forks` | `z_forks` | unknown |
| bincode-fork | local path | `z_forks` | absent | unknown |
| hyper-alloy-core-fork | local path, 6 occ. | absent | absent | unknown |
| reth | git `reth-e231042ee7db3fb7` rev `3212af2` | `z_forks/reth-{chainspec, ethereum-forks, rpc-eth-types, rpc-server-types}` | absent | #94 short rev `3212af2` only |
| revm-precompile | crates.io `16.0.0` | `z_forks/revm-precompile`, 12 occ. | absent | unknown in #115 |

The checkout directory hash `e231042ee7db3fb7` is Cargo's hash of the git URL, so it identifies the URL only for
someone who already knows the URL. The next section recovers it.

### Origin collisions

`make path-origin` attributes every source path to one origin and reports any package reached from more than one
(`tools/path_origin.py`, `sourcing-94.json`, `sourcing-115.json`, reruns byte-identical). Distinct paths only, so
the totals here are lower than the raw occurrence counts above.

#94, 670 paths: 453 registry (131 crates), 172 workspace, 25 `hyper-fork`, 9 git `reth@3212af2`, 6
`hyper-alloy-core-fork`, 4 `bincode-fork`, 1 `hyper-tls-fork`.

#115, 703 paths: 459 `z_vendor` (154 crates), 197 workspace-relative, 25 `z_forks/hyper-fork`, 12
`z_forks/revm-precompile`, 4 `z_forks/bincode-fork`, 2 `z_forks/reth-rpc-eth-types`, and one each for
`z_forks/reth-chainspec`, `z_forks/reth-ethereum-forks`, `z_forks/reth-rpc-server-types`, `z_forks/hyper-tls-fork`.

Exactly one package is built from two origins, in both targets: `hyper`. #94 keeps the registry extract at
`0.14.29` (15 paths) beside the fork (25 paths); #115 keeps a vendored `hyper` (20 paths) beside the fork. So the
override is not a `[patch]` that displaces the registry copy — a patch leaves no registry extract behind — and both
copies are compiled.

Four crates in #94 exist only under an override and never in the registry: `bincode`, `hyper-tls`,
`alloy-primitives`, `alloy-sol-types`. In #115 all four are vendored, and `bincode`/`hyper-tls` additionally keep
their fork. No `reth-*` name appears in the #94 registry at all; that graph is the git checkout alone.

For a rebuild: every origin listed above has to exist at the recorded path, or the paths change and the digest
cannot match. The package a fork directory replaces is a name mapping, not a read value, and no base version of any
fork is known yet.

### Git dependency source

`reth-e231042ee7db3fb7` is `~/.cargo/git/checkouts/reth-<short_hash>/3212af2`. The suffix is Cargo's
`short_hash` of the canonical URL: last path segment, `-`, then `hex(hash_u64(url).to_le_bytes())` over
`StableSipHasher128`, with a trailing slash stripped, `https` forced, a `github.com` path lowercased and a `.git`
suffix dropped. `tools/git_fork_id.py` recomputes it offline; `make fork-id` re-derives the observed suffix from
`reth-url-candidates.txt`. The siphash core is checked against the 64 rows of the upstream vector, one of them kept
as a regression case.

Candidates were the 14 distinct `*/reth` repositories among 77 commits named `3212af2` (GitHub commit search).
Exactly one hashes to the observed suffix:

```
MATCH e231042ee7db3fb7  https://github.com/paradigmxyz/reth
```

`3212af2` there is `3212af2d85a54eb207661361ac9fe1d7de4b5b8e`, `chore: release 1.1.5 (#13700)`, 2025-01-07. The
dependency is upstream reth at the v1.1.5 release commit, not a private fork, and the five crates in the recorded
paths are stock upstream layout. That dates #94 after 2025-01-07 and removes the need to identify a fork owner before
a build. An 8-hex match is 32 bits of the fold: strong, not proof, since no cargo run has reproduced the directory
name.

### Override base versions

`make override-versions` bounds what each override forks without a manifest. A panic location leaves `path:line`, so
the image holds a partial file list per override. The tool keeps the crates.io versions that contain every recorded
path and whose files are at least as long as the highest recorded line, then drops any version whose own `Cargo.toml`
needs a dependency version the image does not contain. Tarballs are cached under `work/prov/crates` with their
SHA-256. Output: `override-versions-94.json`.

| Override | Paths | Line floors | Candidates | Excluded |
| --- | ---: | ---: | --- | --- |
| `hyper-fork` | 25 | 17 | `0.14.9`–`0.14.32` (24) | 214 by missing path, 7 by short file |
| `bincode-fork` | 4 | 0 | `2.0.0`, `2.0.1` | 54 by missing path |
| `hyper-tls-fork` | 1 | 0 | `0.5.0` | 15 by dependency requirement, all needing a `hyper` major absent from #94 |
| `hyper-alloy-core-fork` `primitives` / `sol-types` | 2 / 4 | 0 | `0.8.4`–`1.7.3`, shared between both (48) | 31 / 4 by missing path |

The bounds are still ranges, and the package behind each directory is a mapping from the directory name, not a read
value: `hyper-fork` could be a renamed package at `0.14.29`. A `Cargo.toml` or `Cargo.lock` from the build host would
turn the mapping into a read value; until then the range is what the bytes support.

## Implementation and comparison

### Inferred settings

| Setting | Value | Basis |
| --- | --- | --- |
| Linker | `rust-lld` from the stamped toolchain | The LLD build path is `/checkout/src/llvm-project`, and LLD matches the toolchain's own LLVM version. Rust uses `rust-lld` by default on `x86_64-unknown-linux-gnu` since 1.90. |
| Build host | Ubuntu 24.04, glibc 2.39 | GCC stamp names the `24.04` package. The highest `GLIBC_` version needed is 2.39. |
| Target triple | `x86_64-unknown-linux-gnu` | x86-64 ELF with the glibc loader. The binary contains no triple string. |
| Global allocator | jemalloc 5.3.0 | Version string present. The crate name and version are not visible. |
| Panic strategy (node only) | `unwind` | `.gcc_except_table` is 2996100 bytes (#94) and 2900276 bytes (#115). Linked C++ code also uses this table, so the size is supporting evidence, not proof. The visor table (235764 bytes) is too small to decide. |
| Debug assertions | off | The std `unsafe precondition(s) violated` message is absent. This is weak evidence, because the message appears only if a checked API is used in a crate built with debug assertions. |
| Stripping | symbols and debug info removed | No `.symtab` and no `.debug*`. Cargo `strip` and a separate `strip` produce the same result. |

### Deterministic Linux build plan

This plan describes the build for anyone who has the source. It has not been run.

1. Use an Ubuntu 24.04 x86-64 image with `build-essential`, `pkg-config`, and `libssl-dev` (OpenSSL 3.0). Record the image digest.
2. Install the exact toolchain with `rustup toolchain install 1.94.1 --profile minimal` (for #94) or `1.95.0` (for #115). Confirm the commit with `rustc -vV`.
3. Put the workspace at `/home/ubuntu/hl/code_Mainnet` and run as a user whose home is `/home/ubuntu`. The binaries embed absolute paths, so other paths change `.rodata` and the build ID.
4. For #94, use `CARGO_HOME=/home/ubuntu/.cargo`, the reth git dependency at short rev `3212af2`, and the four forks at `/home/ubuntu/hl/*-fork`. For #115, use `cargo vendor` output in `z_vendor/` and the eight forks in `z_forks/`.
5. Build with `cargo build --release --locked --offline`, using the committed `Cargo.lock` and the release profile from `Cargo.toml`.
6. Set `SOURCE_DATE_EPOCH` and keep `RUSTFLAGS` empty unless the original build config says otherwise.
7. Compare the result with `tools/build_provenance.py --diff`, then compare the build ID and the full SHA-256.

### Unresolved fields

| Field | What would resolve it |
| --- | --- |
| `opt_level` | A rebuild of a known function at each opt level, compared by instruction pattern |
| `lto` | Cross-crate inlining evidence, or a matched rebuild |
| `codegen_units` | Function order and partitioning in a matched rebuild |
| `overflow_checks` | Callers of the core overflow panic helpers inside first-party code |
| `target_cpu_features` | Unconditional AVX or BMI use outside runtime-dispatched paths |
| `frame_pointers` | A prologue survey over FDE-bounded functions |
| `rustflags` | The original build config |
| `fork_base_versions` | A manifest or lock from the build host. The version is now bounded per directory; the package name is still a mapping |
| `cargo_lock` | The original `Cargo.lock`. Paths give versions for #94 registry crates and only 18 of 131 vendored #115 directories |
| `first_party_crate_versions` | First-party paths carry no versions |
| `panic_strategy` (visor only) | Map LSDA owners to Rust functions |

Two more questions are open:

- The `clang version 2x.1.0-rc2` stamps match the toolchain's LLVM major version, not Ubuntu 24.04's packaged clang. They may come from C objects in the Rust toolchain itself. Which input object carries them is not checked.
- The package each override directory declares is unknown. The version behind it is bounded, not read.

## Results and limitations

- `tools/build_provenance.py --check` passes for all three targets at upstream `6fb8631`. `tests/test_build_provenance.py` regenerates each record from the verified target and compares it with the committed JSON. It also runs synthetic-ELF tests that need no LFS data.
- `make path-origin` writes `sourcing-{94,115}.json`; the origin tests cover the mapping and the collision row, and regenerate both files from the verified targets.
- `make fork-id` re-derives the reth checkout suffix; `GitForkIdTests` covers the siphash vector, the observed suffix, canonicalisation and the scp rejection.
- `make override-versions` writes `override-versions-94.json`; `OverrideVersionTests` covers the line-floor, requirement and alloy-pairing filters on synthetic crates. Both candidate sets are lower bounds on what the version can be.
- Counts come from string scans over the whole file. An occurrence count is a count of matching byte strings, not of functions or call sites.
- The tool parses path strings. A crate that leaves no panic location or path string in the binary is missing from these lists, so each list is a lower bound. The same holds for the origin matrix: a fork that leaves no path is invisible there, so the collision list is a lower bound too.
- No progress gate is requested.

Next question: which package each override directory declares. A `Cargo.toml` or `Cargo.lock` from the build host answers it directly; failing that, the `[patch]` or `[replace]` shape that produced both copies of `hyper` is still unread.
