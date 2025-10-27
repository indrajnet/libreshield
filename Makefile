#
# Copyright (C) 2025 Indraj Gandham <support@indraj.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#


DC := gdc
DEBUG := -g -fdebug -fbounds-check=on -funittest
RELEASE := -s -fno-assert \
-fbounds-check=on \
-fno-invariants \
-fno-postconditions \
-fno-preconditions \
-fno-switch-errors

ELF_HARDEN := -fPIE
SO_HARDEN := -fPIC -shared

AMD64_HARDEN := -fcf-protection=full
AARCH64_HARDEN := -mbranch-protection=standard

HARDEN := -fstack-clash-protection \
-fstack-protector-strong

LD_HARDEN := -pie \
-Wl,-z,nodlopen \
-Wl,-z,noexecstack \
-Wl,-z,relro \
-Wl,-z,now \
-Wl,--as-needed \
-Wl,--no-copy-dt-needed-entries

DFLAGS := -O2 -Werror

ELF_AMD64_HARDEN := $(ELF_HARDEN) \
$(AMD64_HARDEN) \
$(HARDEN)

ELF_AARCH64_HARDEN := $(ELF_HARDEN) \
$(AARCH64_HARDEN) \
$(HARDEN)

SO_AMD64_HARDEN := $(SO_HARDEN) \
$(AMD64_HARDEN) \
$(HARDEN) \

SO_AARCH64_HARDEN := $(SO_HARDEN) \
$(AARCH64_HARDEN) \
$(HARDEN) \

LDFLAGS := -lsodium -loqs
OUT := tests
CONFIG := $(DFLAGS) $(DEBUG) $(ELF_AMD64_HARDEN)

OBJS := $(patsubst src/%.d, obj/%.o, $(wildcard src/*.d))

.PHONY: all clean
all: $(OUT)

clean:
	rm -rf $(OUT) obj/*

$(OUT): $(OBJS)
	$(DC) $(CONFIG) $(LD_HARDEN) -o $(OUT) $(OBJS) $(LDFLAGS)

obj/libreshield.o: src/libreshield.d | src/sodium.c src/oqs.c
	$(DC) $(CONFIG) -I src -c src/libreshield.d -o obj/libreshield.o

obj/tests.o: src/tests.d src/libreshield.d
	$(DC) $(CONFIG) -I src -c src/tests.d -o obj/tests.o
