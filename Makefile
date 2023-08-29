# Name of the cover profile
COVER_PROFILE := cover.out

IMAGE_TAG := v0.0.7

# OS
UNAME := $(shell uname -s)

# allows CI to specify whether to have race detection on / off
ifeq ($(RACE_DETECTOR),1)
	RACE_FLAG := -race
else
	RACE_FLAG :=
endif

# `ADX_SUPPORT` is 1 if ADX instructions are supported and 0 otherwise.
ifeq ($(UNAME),Linux)
# detect ADX support on the CURRENT linux machine.
	ADX_SUPPORT := $(shell if ([ -f "/proc/cpuinfo" ] && grep -q -e '^flags.*\badx\b' /proc/cpuinfo); then echo 1; else echo 0; fi)
else
# on non-linux machines, set the flag to 1 by default
	ADX_SUPPORT := 1
endif

# the crypto package uses BLST source files underneath which may use ADX insructions.
ifeq ($(ADX_SUPPORT), 1)
# if ADX insructions are supported, default is to use a fast ADX BLST implementation 
	CRYPTO_FLAG := ""
else
# if ADX insructions aren't supported, this CGO flags uses a slower non-ADX BLST implementation 
	CRYPTO_FLAG := "-O -D__BLST_PORTABLE__"
endif
CGO_FLAG := CGO_CFLAGS=$(CRYPTO_FLAG)

# format C code
.PHONY: c-format
c-format:
	clang-format -style=llvm -dump-config > .clang-format
	clang-format -i *.c
	clang-format -i *.h
	rm -f .clang-format
	git diff --exit-code

# sanitize C code
# cannot run on macos
.SILENT: c-sanitize
c-sanitize:
# - memory sanitization (only on linux and using clang) - (could use go test -msan)
# - address sanitization and other checks (only on linux)
	if [ $(UNAME) = "Linux" ]; then \
		$(CGO_FLAG) CC="clang -O0 -g -fsanitize=memory -fno-omit-frame-pointer -fsanitize-memory-track-origins" \
		LD="-fsanitize=memory" go test; \
		if [ $$? -ne 0 ]; then exit 1; fi; \
		\
		$(CGO_FLAG) CC="-O0 -g -fsanitize=address -fno-omit-frame-pointer -fsanitize=leak -fsanitize=undefined -fno-sanitize-recover=all -fsanitize=float-divide-by-zero -fsanitize=float-cast-overflow -fno-sanitize=null -fno-sanitize=alignment" \
		LD="-fsanitize=address -fsanitize=leak" go test; \
		if [ $$? -ne 0 ]; then exit 1; fi; \
	else \
		echo "sanitization is only supported on Linux"; \
	fi; \

# Go tidy
.PHONY: go-tidy
go-tidy:
	go mod tidy -v
	git diff --exit-code

# Go lint
.PHONY: go-lint
go-lint:
lint: go-tidy
	# revive -config revive.toml
	golangci-lint run -v ./...
	
	


# test all packages
.PHONY: test
test:
# root package
	$(CGO_FLAG) go test -coverprofile=$(COVER_PROFILE) $(RACE_FLAG) $(if $(JSON_OUTPUT),-json,) $(if $(NUM_RUNS),-count $(NUM_RUNS),) $(if $(VERBOSE),-v,)
# sub packages
	$(CGO_FLAG) go test -coverprofile=$(COVER_PROFILE) $(RACE_FLAG) $(if $(JSON_OUTPUT),-json,) $(if $(NUM_RUNS),-count $(NUM_RUNS),) $(if $(VERBOSE),-v,) ./hash
	$(CGO_FLAG) go test -coverprofile=$(COVER_PROFILE) $(RACE_FLAG) $(if $(JSON_OUTPUT),-json,) $(if $(NUM_RUNS),-count $(NUM_RUNS),) $(if $(VERBOSE),-v,) ./random

.PHONY: docker-build
docker-build:
	docker build -t gcr.io/dl-flow/golang-cmake:latest -t gcr.io/dl-flow/golang-cmake:$(IMAGE_TAG) .

.PHONY: docker-push
docker-push:
	docker push gcr.io/dl-flow/golang-cmake:latest 
	docker push "gcr.io/dl-flow/golang-cmake:$(IMAGE_TAG)"
