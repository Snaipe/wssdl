LUA := lua
WS_PLUGIN_DIR := $(HOME)/.config/wireshark/plugins/

bootstrap: wssdl.lua

wssdl.lua:
	$(LUA) pack.lua src > wssdl.lua

install: $(HOME)/.config/wireshark/plugins/ | bootstrap
	cp -f wssdl.lua $^

$(HOME)/.config/wireshark/plugins/:
	mkdir $@

clean:
	$(RM) wssdl.lua

.PHONY: bootstrap install clean
