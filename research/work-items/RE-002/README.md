# RE-002: build provenance fingerprints for #94 and #115

- Component ID: foundation (build provenance)
- Target release and full SHA-256: node #94 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
  node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (separate target, reported apart)
- Source commit / reference commit: repository `6fb86319763b30860f92b9da746cbe4f9b637573`;
  can1357 reference submodule `999556f6e0a474b8312db96ec3149e1c44e97c23`
- Claim status: observation for every recorded string; the build plan is inference and stays unexecuted
- Scope included: `.comment`, dynamic linkage, unwind imports, build root/user/cargo-home layout, path and git forks,
  registry crates with versions, `rustc` library prefix, `--remap-path-prefix` evidence, a deterministic Linux
  build plan for both targets. Excluded: any actual build, dependency edges, feature flags, `-C` options that
  leave no trace, and the whole function/behavior comparison.

This packet covers one bounded slice of RE-002. It does not request a component gate.

## Reproduce

```sh
./scripts/setup.sh
make verify test catalogue-check
make provenance        # tools/build_provenance.py --release 94 and --release 115
make fork-id           # tools/git_fork_id.py over the candidate URLs, must print one hit
```

Host for this run: macOS 15 arm64, Python 3.9.6, no cargo/rustc/docker on PATH. The tool is stdlib-only and
reads the verified artifact without executing it. It re-hashes the file and fails if the digest differs from
`provenance/artifacts.json`. Output goes to `work/prov/<release>.json`; the two JSON files beside this record
are the retained copies and rerun byte-identically.

The extractor fails closed on: a non-ELF64-LE input, a missing or duplicated `.comment`, a `.comment` larger
than 4 KiB or not NUL-terminated, a truncated or unsorted section table, more than one build root, and more
than 200 distinct rows for one pattern. Tests in `tests/test_research_tools.py` (`ProvenanceTests`, 6 cases,
synthetic ELF) cover comment extraction, absolute paths preceded by unrelated rodata bytes, relative paths,
the three malformed-comment rejections and the two-root rejection.

`tools/git_fork_id.py` recomputes the cargo checkout suffix for a candidate URL instead of guessing it: cargo
canonicalizes the URL (`CanonicalUrl::new`), hashes it as a `str` with `StableSipHasher128` (SipHash-1-3, keys
0/0), finishes as `low * 3 + high` and writes the result little-endian. `--selftest` runs the hasher against the
upstream 1-3 test vector, 64 lengths. `GitForkIdTests` (6 cases) pins five vector lengths, the canonicalization
rules, the scp-style rejection and the observed suffix. `make test` runs 32 tests, all passing.

## Evidence

`.comment`, in stored order, both targets:

- #94: `GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`, `clang version 21.1.0-rc2`,
  `Linker: LLD 21.1.8 (/checkout/src/llvm-project/llvm 00d23d10dc48c6bb9d57ba96d4a748d85d77d0c7)`,
  `rustc version 1.94.1 (e408947bf 2026-03-25)`
- #115: `rustc version 1.95.0 (59807616e 2026-04-14)`,
  `Linker: LLD 22.1.2 (/checkout/src/llvm-project/llvm 1cb4e3833c1919c2e6fb579a23ac0e2b22587b7e)`,
  `GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`, `clang version 22.1.0-rc2`

The `GCC:` string is not decoration: `.comment` only carries it because C and C++ objects were compiled, and
both binaries import `libstdc++.so.6`. The `rustc version` line is the compiler identity; the LLD line pins the
linker and the rustc-side LLVM checkout that shipped it. `/checkout/src/llvm-project/llvm` is the build path
inside the rustc distribution, so the linker is the one bundled with that compiler, not a distribution LLD.

Dynamic linkage, both targets, same list and order: `libstdc++.so.6`, `libssl.so.3`, `libcrypto.so.3`,
`libgcc_s.so.1`, `libm.so.6`, `libc.so.6`, `ld-linux-x86-64.so.2`. Glibc target, not musl; OpenSSL 3 is a
runtime dependency, not statically vendored. `.note.ABI-tag` is Linux 3.2.0 on both.

Unwind is linked in, so the profile is `panic = "unwind"`, not abort: both import `_Unwind_Resume`,
`_Unwind_RaiseException`, `_Unwind_Backtrace` and `__gxx_personality_v0` as undefined dynamic symbols, and both
carry `.eh_frame`/`.eh_frame_hdr`.

Both are `ET_DYN` PIE with `GNU_RELRO`, no `.symtab`, no `.strtab` and no `.debug_*`: stripped, and therefore no
`DW_AT_producer` anywhere. Build IDs differ per target: #94 `29a7b9d6c31d0c687c376a834eba4f3ddaac660b`,
#115 `ac2880fcda5e49007a8e4fb1ea6aa7dd1b2eae01`.

Layout, from panic-location paths (absolute count 732 on #94, 499 on #115):

- #94 build root `/home/ubuntu/hl`, build user `ubuntu`, cargo home `/home/ubuntu/.cargo`. Under the root:
  `code_Mainnet/` with `base`, `db`, `evm_rpc`, `global_constants`, `info_server`, `l1`, `net_utils`, `node`,
  and four sibling path forks `hyper-fork`, `bincode-fork`, `hyper-alloy-core-fork` (crates `primitives`,
  `sol-types`), `hyper-tls-fork`.
- One git fork: `reth-e231042ee7db3fb7` at revision `3212af2`, crates `chainspec`, `ethereum/evm`, `primitives`,
  `rpc/rpc-eth-types`, `rpc/rpc-server-types`. The directory name is a hash, not a label, and it resolves:
  `short_hash("https://github.com/paradigmxyz/reth")` is `e231042ee7db3fb7`, so the dependency is upstream reth,
  not a fork. Confirmed twice, the second time outside cargo: `3212af2` exists in that repository as
  `3212af2d85a54eb207661361ac9fe1d7de4b5b8e`, release 1.1.5, 2025-01-07. None of the 48 other candidate
  owner/name pairs from `reth-url-candidates.txt` reproduce the suffix.
- Registry `index.crates.io-1949cf8c6b5b557f`: 118 distinct crates, 809 references, versions included in the
  evidence file. Notable native-build crates: `rocksdb 0.21.0`, `blst 0.3.13`, `c-kzg 1.0.3`,
  `secp256k1-sys 0.10.0`, `bzip2-sys 0.1.11+1.0.8`, `openssl-sys 0.9.107`, `aurora-engine-modexp 1.1.0`.
  Two versions of `sha2` (`0.10.8`, `0.9.9`), `socket2` (`0.4.10`, `0.5.7`) and `foldhash` (`0.1.4`, `0.2.0`)
  are present, so the graph is not deduplicated to one version per crate.
- #115 is a different build shape, not a rerun: `code_Mainnet/z_vendor/` with 131 vendored crates (dir names
  carry versions when they collide, e.g. `hashbrown-0.15.2`, `secp256k1-0.30.0`, `ark-ff-0.5.0`), forks under
  the relative `z_forks/` (244 relative source paths, e.g. `base/src/api_secrets.rs`), zero registry paths,
  zero git checkouts. Vendored crates that #94 took from the registry include `h2`, `hyper`, `alloy-*`,
  `revm-*`, so #115 also moved dependency sourcing, not just compiler versions.

No path remapping: #94 keeps absolute `/home/ubuntu/...` paths. #115 keeps `/home/ubuntu/hl/code_Mainnet/...`
for its own crates but relative `z_forks/...` for forks, which is what cargo passes for a path dependency
declared relative to the workspace.

## Implementation and comparison

Not applicable to a Rust path; no build ran. What the strings support, in order of confidence:

1. Observed: rustc/LLD/clang/gcc identities above, glibc dynamic linkage, OpenSSL 3, C++ runtime,
   `panic=unwind`, PIE+RELRO, stripped, no remap prefix, build root and cargo home, the crate and fork lists.
2. Inferred: Ubuntu 24.04.1 build host as user `ubuntu` with `HOME=/home/ubuntu`, cargo invoked from
   `/home/ubuntu/hl` so that `code_Mainnet` is the workspace member root; `--release` build of a
   `hl-node`-named binary from the `node` crate; the four sibling dirs are `[patch]`/path overrides of
   crates.io packages; the `reth` fork is a git dependency pinned at `3212af2`.
3. Unresolved, and the reason this stays a plan: `-C opt-level`, `lto`, `codegen-units`, `target-cpu`,
   `debuginfo` level, incremental, `RUSTFLAGS`, `--cfg` feature sets, `-C link-arg`, the reth fork URL, the
   full crate graph and every edge, and which clang binary produced the clang objects (no distro clang in
   24.04 is 21.1.0-rc2).

Deterministic plan, both targets, to be executed only with authorization:

```sh
# image and identity
docker run --platform linux/amd64 -it ubuntu:24.04.1        # release string matches the GCC stamp
useradd -m ubuntu && su ubuntu                              # HOME=/home/ubuntu, as in the paths
apt-get install -y gcc=13.3.0-6ubuntu2~24.04.1 g++ libssl-dev libstdc++-13-dev
# toolchain: rustup 1.94.1 (profile minimal, rustfmt+clippy) for #94, 1.95.0 for #115
# linker: rust-lld from the same toolchain, pinned at the .comment LLVM revision
git clone --recursive <fork> /home/ubuntu/hl && cd /home/ubuntu/hl/code_Mainnet
cargo build --release --locked
sha256sum target/release/hl-node    # must equal the manifest digest before any comparison
```

Ordering that matters, all from the strings: same compiler and linker revisions, same build path
(`/home/ubuntu/hl`) because paths are embedded, same cargo home, same registry index hash, and per target the
same dependency sourcing (#94 registry plus git fork, #115 `z_vendor`/`z_forks`). Anything that changes a path
changes the strings and the digest, so a first pass must match layout before flags.

Reference-tree drift already visible: the can1357 tree has `bincode_fork/` flat (`de/impls.rs`, `enc/write.rs`)
while the build used `bincode-fork/src/` (`de/decoder.rs`, `de/impls.rs`, `enc/write.rs`, `lib.rs`); the tree has
no `hyper-fork`, `hyper-alloy-core-fork`, `hyper-tls-fork` and no manifests. Crate names match the workspace,
directory names and internal layout do not, so the reference is a lead for identity, not a build source.

## Results and limitations

Machine-readable: `build-94.json`, `build-115.json` (full SHA-256, comment list, layout, registry and git rows,
unresolved list). Counts above are exact for what the extractor sees; the registry list is a lower bound,
because a crate appears only if one of its paths survives as a string. Crate versions come from path text and a
stale directory can survive a version bump. No dependency edge, feature flag or build order is claimed. The
`z_vendor` crate set is not asserted complete either.

Both `.comment` sections are self-consistent with a single build each: the gcc stamp is identical across the two
targets and the rustc/LLD pairs are internally consistent per target, which is weak corroboration that neither
file was post-processed. Weak, because nothing here proves it.

No gate is requested: RE-002 also wants the crate graph, fork URLs and the executed two-build result.

The reth dependency is therefore pinned to a public source: `https://github.com/paradigmxyz/reth` at
`3212af2d85a54eb207661361ac9fe1d7de4b5b8e`. A build needs no private fork for it, only that revision. The four
`*-fork` siblings are path overrides and leave no URL, so they stay unresolved.

Next question: does the workspace still carry the crates.io `reth-*` graph that the four path overrides shadow, so
that a build without them fails on the same versions the strings show, or do the overrides change the resolution
set? The strings show the patched crate names (`primitives`, `sol-types`) under both the overrides and the git
checkout, which is what a `[patch]` for a renamed package looks like, but no manifest survives to confirm it.
