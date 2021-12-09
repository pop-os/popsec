prefix ?= /usr/local
bindir = $(prefix)/bin

TARGET = debug
DEBUG ?= 0
ifeq ($(DEBUG),0)
	TARGET = release
	ARGS += --release
endif

VENDOR ?= 0
ifneq ($(VENDOR),0)
	ARGS += --frozen
endif

BIN = target/$(TARGET)/popsec-gtk

all: $(BIN)

clean:
	rm -rf target

distclean: clean
	rm -rf .cargo vendor vendor.tar

$(BIN): Cargo.toml Cargo.lock src/lib.rs vendor-check
	cargo build --manifest-path gtk/Cargo.toml $(ARGS)

install: $(BIN)
	install -Dm0755 $(BIN) "$(DESTDIR)$(bindir)/popsec-gtk"

vendor:
	rm .cargo -rf
	mkdir -p .cargo
	cargo vendor | head -n -1 > .cargo/config
	echo 'directory = "vendor"' >> .cargo/config
	tar cf vendor.tar vendor
	rm -rf vendor

vendor-check:
ifeq ($(VENDOR),1)
	rm vendor -rf && tar xf vendor.tar
endif
