LUA := lua
WS_PLUGIN_DIR := $(HOME)/.config/wireshark/plugins

bootstrap: wssdl.lua

wssdl.lua: $(wildcard src/wssdl/*.lua)
	$(LUA) pack.lua src > wssdl.lua

install: | bootstrap
	mkdir -p $(WS_PLUGIN_DIR)
	cp -f wssdl.lua $(WS_PLUGIN_DIR)

uninstall:
	$(RM) $(WS_PLUGIN_DIR)/wssdl.lua

clean:
	$(RM) wssdl.lua

.PHONY: bootstrap install clean
