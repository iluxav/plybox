# plybox — build, install, uninstall.
#
#   make install            build the static binary and copy it to $(BINDIR)
#   make uninstall          remove it (sessions and images are left alone)
#   make test               unit tests
#   make lab                the 41-probe suite against the built binary
#   make lab-sessions       session lifecycle + resume checks (no network)
#
# The shipped binary is static musl: it runs as the supervisor on the host
# and as `plybox __inner` inside any image, so it must not depend on a libc.

PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
TARGET := x86_64-unknown-linux-musl
BIN    := plybox/target/$(TARGET)/release/plybox

.PHONY: build install uninstall test lab lab-sessions clean

build:
	@rustup target list --installed | grep -qx $(TARGET) || rustup target add $(TARGET)
	cd plybox && cargo build --release --target $(TARGET)

# A real copy, not a link: what you test is exactly what was just built,
# and later rebuilds do not change the installed binary behind your back.
install: build
	install -d $(BINDIR)
	rm -f $(BINDIR)/plybox
	install -m 755 $(BIN) $(BINDIR)/plybox
	@echo "installed $(BINDIR)/plybox — $$($(BINDIR)/plybox version)"
	@command -v plybox >/dev/null 2>&1 || echo "note: $(BINDIR) is not on your PATH"

uninstall:
	rm -f $(BINDIR)/plybox
	@echo "removed $(BINDIR)/plybox"
	@echo "kept: sessions in $${XDG_STATE_HOME:-$$HOME/.local/state}/plybox, images in $${XDG_DATA_HOME:-$$HOME/.local/share}/plybox"
	@echo "      (plybox sessions --prune before uninstalling clears applied/empty sessions)"

test:
	cd plybox && cargo test --release

lab: build
	bash lab/v0/run.sh

lab-sessions: build
	bash lab/sessions/run.sh $(abspath $(BIN))
	python3 lab/sessions/resume.py $(abspath $(BIN))

clean:
	cd plybox && cargo clean
