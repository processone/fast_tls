REBAR ?= rebar

all: src

src:
	$(REBAR) get-deps compile

clean:
	$(REBAR) clean

test:
	$(REBAR) skip_deps=true eunit

.PHONY: clean src
