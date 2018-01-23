ifeq ($(OS),Windows_NT)
OBJECTS += async.o gerror.o
OBJECTS += $(patsubst %.c,%.o,$(wildcard src/windows/*.c))
else
OBJECTS += $(patsubst %.c,%.o,$(wildcard src/libusb/*.c))
endif

CPPFLAGS += -Iinclude -I. -I../
CFLAGS += -fPIC

LDFLAGS += -L../gimxlog
LDLIBS += -lgimxlog

ifneq ($(OS),Windows_NT)
LDLIBS += -lusb-1.0
else
LDLIBS += -lhid -lsetupapi
endif

include Makedefs

ifeq ($(OS),Windows_NT)
async.o: ../gimxcommon/src/windows/async.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<

gerror.o: ../gimxcommon/src/windows/gerror.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
endif
