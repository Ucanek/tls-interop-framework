# Build-time artifacts (not compiled at runtime by Python wrappers).
CC ?= gcc
GNUTLS_HOOK_DIR := src/wrappers/gnutls
GNUTLS_HOOK_SRC := $(GNUTLS_HOOK_DIR)/gnutls_session_hook.c
GNUTLS_HOOK_SO := $(GNUTLS_HOOK_DIR)/gnutls_session_hook.so
GNUTLS_PKG_LIBS := $(shell pkg-config --cflags --libs gnutls 2>/dev/null)
ifeq ($(GNUTLS_PKG_LIBS),)
GNUTLS_PKG_LIBS := -lgnutls
endif

.PHONY: all gnutls-hook clean clean-gnutls-hook

all: gnutls-hook

gnutls-hook: $(GNUTLS_HOOK_SO)

$(GNUTLS_HOOK_SO): $(GNUTLS_HOOK_SRC)
	$(CC) -shared -fPIC -o $@ $< $(GNUTLS_PKG_LIBS)

clean: clean-gnutls-hook

clean-gnutls-hook:
	rm -f $(GNUTLS_HOOK_SO)
