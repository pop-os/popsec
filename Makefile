prefix ?= /usr
sysconfdir ?= /etc
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
libdir = $(exec_prefix)/lib
includedir = $(prefix)/include
datarootdir = $(prefix)/share
datadir = $(datarootdir)

SRC = \
	Cargo.toml Cargo.lock Makefile rust-toolchain \
	$(shell find daemon gtk src tpm2-totp-sys -type f)

.PHONY: all clean distclean install uninstall update

PKG=popsec
DAEMON=$(PKG)-daemon
GTK=$(PKG)-gtk

ARGS = --release
VENDORED ?= 0
ifeq ($(VENDORED),1)
	ARGS += --frozen
endif

all: target/release/$(DAEMON) target/release/$(GTK)

clean:
	cargo clean

distclean: clean
	rm -rf .cargo vendor vendor.tar.xz

install: install-daemon install-gtk

install-daemon: target/release/$(DAEMON)
	install -D -m 0755 "target/release/$(DAEMON)" "$(DESTDIR)$(libdir)/$(PKG)/$(DAEMON)"
	install -D -m 0644 "data/$(DAEMON).conf" "$(DESTDIR)$(sysconfdir)/dbus-1/system.d/$(DAEMON).conf"
	install -D -m 0644 "debian/$(DAEMON).service" "$(DESTDIR)$(sysconfdir)/systemd/system/$(DAEMON).service"

install-gtk: target/release/$(GTK)
	install -D -m 0755 "target/release/$(GTK)" "$(DESTDIR)$(bindir)/$(GTK)"

uninstall: uninstall-gtk uninstall-daemon

uninstall-daemon:
	rm -f "$(DESTDIR)$(libdir)/$(PKG)/$(DAEMON)"
	rm -f "$(DESTDIR)$(sysconfdir)/dbus-1/system.d/$(DAEMON).conf"
	rm -f "$(DESTDIR)$(sysconfdir)/systemd/system/$(DAEMON).service"

uninstall-gtk:
	rm -f "$(DESTDIR)$(bindir)/$(GTK)"

update:
	cargo update

vendor:
	mkdir -p .cargo
	cargo vendor | head -n -1 > .cargo/config
	echo 'directory = "vendor"' >> .cargo/config
	tar pcfJ vendor.tar.xz vendor
	rm -rf vendor

target/release/$(DAEMON) target/release/$(GTK): $(SRC)
ifeq ($(VENDORED),1)
	tar pxf vendor.tar.xz
endif
	cargo build $(ARGS)
	cargo build -p $(DAEMON) $(ARGS)
	cargo build -p $(GTK) $(ARGS)
