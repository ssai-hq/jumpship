SHELL := /bin/sh
.DEFAULT_GOAL := help
.SUFFIXES:

ifneq ($(shell python3 ./scripts/packets/check make-safety),JUMPSHIP_PACKET_MAKE_SAFETY_OK)
$(error packet Make safety check failed)
endif

# The root dispatcher is intentionally target-free. Packet fragments own every
# public target and hidden hook; the pre-include gate validates their safety.
include $(sort $(wildcard mk/packets/P??.mk))
