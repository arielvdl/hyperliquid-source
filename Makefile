PYTHON ?= python3
.PHONY: setup pull fetch verify test reproduce doctor index extents catalogue catalogue-check provenance fork-id path-origin override-versions rea-install rea-doctor rea-mcp rea-smoke rea-mcp-check rea-native-smoke
setup:
	./scripts/setup.sh
pull:
	git submodule update --init --recursive
	git lfs pull
	git -C references/can1357-hl lfs pull
fetch:
	$(PYTHON) tools/artifacts.py fetch
verify:
	$(PYTHON) tools/artifacts.py verify
	$(PYTHON) tools/verify_imports.py
test:
	$(PYTHON) -m unittest discover -s tests -v
provenance:
	$(PYTHON) tools/build_provenance.py
path-origin:
	$(PYTHON) tools/path_origin.py --release 94
	$(PYTHON) tools/path_origin.py --release 115
reproduce:
	$(PYTHON) tools/reproduce.py
doctor:
	$(PYTHON) tools/doctor.py
index:
	$(PYTHON) tools/elf_index.py --release 94
	$(PYTHON) tools/elf_index.py --release 115
extents:
	$(PYTHON) tools/fde_extents.py --release 94
	$(PYTHON) tools/fde_extents.py --release 115
fork-id:
	$(PYTHON) tools/git_fork_id.py --selftest
	$(PYTHON) tools/git_fork_id.py --from-file research/work-items/RE-002-build-provenance/reth-url-candidates.txt --expect e231042ee7db3fb7 --output work/prov/reth-fork-id.json
override-versions:
	$(PYTHON) tools/override_versions.py --release 94 --output research/work-items/RE-002-build-provenance/override-versions-94.json
catalogue:
	$(PYTHON) tools/catalogue.py
catalogue-check:
	$(PYTHON) tools/catalogue.py --check
rea-install:
	$(PYTHON) tools/rea.py install
rea-doctor:
	$(PYTHON) tools/rea.py doctor --provider ghidra --target artifacts/visor/captured/hl-visor --format json
rea-mcp:
	$(PYTHON) tools/rea.py mcp
rea-smoke:
	$(PYTHON) tools/rea_smoke.py
rea-mcp-check:
	$(PYTHON) tools/rea_mcp_check.py --require-ghidra
rea-native-smoke:
	$(PYTHON) tools/rea_mcp_check.py --require-ghidra --native-smoke
