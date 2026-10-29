# RE-001: decoded FDE extents and a validated unwind denominator for #94 and #115

- Component ID: foundation (cross-component function map)
- Target release and full SHA-256: node #94 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
  node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (separate target, reported apart)
- Source commit / reference commit: repository `6fb86319763b30860f92b9da746cbe4f9b637573`;
  can1357 reference submodule `999556f6e0a474b8312db96ec3149e1c44e97c23`
- Claim status: observation for every number below; the extent decoder is tooling, not a reconstruction
- Scope included: `.eh_frame_hdr`/`.eh_frame`/CIE/FDE parsing, range decode, duplicate and gap accounting,
  ELF/`DT_INIT`/`DT_INIT_ARRAY`/`DT_FINI_ARRAY` membership, byte-level `E8` call-target classification.
  Excluded: CFG recovery, disassembly, symbol identity, component ownership, any equivalence claim.

## Reproduce

```sh
./scripts/setup.sh
make verify test catalogue-check
make extents            # tools/fde_extents.py --release 94 and --release 115
```

Host for this run: macOS 15 arm64, Python 3.9.6, no LLVM/Ghidra on PATH. The tool is stdlib-only and
static; it reads the verified artifact, never executes it. Outputs land in `work/fde/` (TSV ranges plus
JSON summary). The two JSON summaries are retained beside this record; the TSVs are regenerable.

`tools/fde_extents.py` reuses `elf_index.sections` and fails closed on: a start that disagrees with the
FDE `initial_location`, an FDE pointer outside `.eh_frame`, an unknown CIE, an unsupported CIE version or
pointer encoding, a truncated record or table, a range that leaves its executable section, and an
unordered index. Range ends are decoded `address_range` values, so the index's next-start upper bound is
no longer used as a size.

Controls (`tests/test_research_tools.py`, `FdeExtentTests`, fixture ELF with a `zR` CIE and two FDEs):
start/`initial_location` disagreement rejected, unsupported header encoding rejected, truncated table
rejected, duplicate start counted rather than merged, relocated `DT_INIT_ARRAY` slot resolved through
`R_X86_64_RELATIVE`, padding and non-padding gaps separated. `make test` runs 26 tests, all passing.

## Evidence

Coordinates are linked VAs as stored in `.eh_frame_hdr`; the ELF is a PIE and no loader rebase is applied.

- #94: 121,299 table entries decode to 121,299 FDEs. 0 duplicate starts, 0 duplicate FDE references
  (`duplicate_fde_references`),
  0 zero-length ranges, 0 start/`initial_location` disagreements. Every start lies in `.text`.
- Range total 69,397,415 B of 70,370,352 B `.text` (98.62%), 0 overlapping bytes. 113,154 gaps hold the
  remaining 972,937 B. 113,024 gaps (907,363 B) are pure `00`/`90`/`cc` padding; 130 gaps (65,574 B)
  contain other bytes and are candidate code without unwind information.
- The two largest non-padding gaps start with `endbr64` after a short `cc` run: `0x54a54dd` (60,675 B) and
  `0x5631543` (2,493 B). They read as hand-written assembly, not padding.
- Direct `E8` targets inside `.text`: 483,120 land exactly on a start, 7,671 inside a range, 108 in a
  non-padding gap interior, 8 on a gap start. 116 targets reach 82 distinct gaps (61,876 B), but only 3 of
  those gaps are non-padding (60,994 B): reach concentrates in the two large assembly regions, not across
  the 130. 106,111 further targets land in `.plt` stubs and 102,044 outside any executable section.
- Entry points: `e_entry = 0x1343c80` is a start and `.text` begins there. `DT_INIT = 0x56600b0` is in
  `.init`, which has no FDE, as expected. All 168 `DT_INIT_ARRAY` slots are `R_X86_64_RELATIVE`-relocated;
  167 resolve to a start. The exception `0x1343d60` and `DT_FINI_ARRAY[0] = 0x1343d20` both sit in the
  195 B assembly gap at `0x1343ca6` directly after `_start`; that gap also holds the first non-start
  call target, `0x1343cb0`.
- #115, same tool and checks: 135,313 entries, 0 duplicates, 0 zero-length, 82,661,417 B of 83,719,936 B
  (98.74%), 126,648 padding gaps (992,583 B), 127 non-padding gaps (65,936 B), 183 targets reaching 151
  distinct gaps, 3 of them non-padding (61,393 B).
  `e_entry = 0x1419320` is a start; 167/168 `DT_INIT_ARRAY` slots resolve to a start; the exception
  `0x14193e0` and `DT_FINI_ARRAY[0] = 0x14193a0` sit in the 202 B gap at `0x1419326`, whose first
  call target is `0x1419330`.
- Both binaries carry three CIEs; one uses `uleb128` absolute `initial_location`, two use `pcrel|sdata4`.
  Decoding the FDE is what makes the header start checkable at all: the header alone only proves ordering
  and section membership.

## Implementation and comparison

Not applicable to a Rust path; this is tooling plus measurement. No Cargo manifest, no build, no
normalization mask, and no matched-body count is claimed.

## Results and limitations

Machine-readable: `node-94-fde.json`, `node-115-fde.json`. Each summary carries the binary digest, the
`range_tsv_sha256` of the regenerated TSV (the TSV itself is not committed, so the digest is a
determinism check for anyone who regenerates it) and `analysis_state`. That state is a declared constant,
not a measurement: it is true by construction, because `analyze` walks every table entry and raises if any
one fails to resolve, and the section check rejects a range that leaves its section. The analysis ran over
both full `.text` sections with no timeout and no range limit. Denominators are the `.text` sizes above;
duplicates and gaps are counted against every entry, not sampled. Section counts are named `fde_entries`
rather than `functions`: they are unwind entries, not a function census.

Unknowns: unwind ranges are compiler-emitted metadata, not proof of a function body or of one function per
entry. `E8` scanning is byte-based, so an `0xe8` byte inside an immediate produces a candidate; the
outside-executable and PLT buckets absorb the obvious false positives but not all. Assembly regions
without FDEs (the two large gaps, `.init`/`.fini`/`.plt`) stay uncounted, so the extents are a lower bound
on code. No component gate is requested: RE-001 also asks for cross-referenced entrypoint validation
beyond ELF/init arrays, which this packet only starts.

Next question: do the 82 call-reachable non-padding gaps begin with `endbr64`/prologues, and does the
`0x1343ca6` cluster map to the standard `_start`/`frame_dummy`/`register_tm_clones` sequence, so the
residual gap set can be split into real code and alignment once and for all?
