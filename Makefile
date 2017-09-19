#
# Copyright (c) 2017, Joyent, Inc.
#
# Makefile: top-level Makefile
#
# This Makefile contains only repo-specific logic and uses included makefiles
# to supply common targets (javascriptlint, jsstyle, restdown, etc.), which are
# used by other repos as well.
#

#
# Tools
#
NPM		 = npm

#
# Files
#
JSON_FILES	 = package.json
JS_FILES	:= bin/haplog $(shell find lib -name '*.js')
JSL_FILES_NODE	 = $(JS_FILES)
JSSTYLE_FILES	 = $(JS_FILES)
JSL_CONF_NODE	 = tools/jsl.node.conf

.PHONY: all
all:
	$(NPM) install

include ./Makefile.targ
