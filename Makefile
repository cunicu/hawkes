CODESIGN_IDENTITY ?= "Apple Development: post@steffenvogel.de"

all: skes

skes: ./assets/entitlements.xml
	go build -o $@ ./cmd
	codesign -f -s ${CODESIGN_IDENTITY} --entitlements ./assets/entitlements.xml $@

.PHONY: all
