# rtp_latch module makefile
#
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=rtcp_relay.so
LIB_DIR = /usr/local/lib
LIBS=

DEFS+=-DKAMAILIO_MOD_INTERFACE

include ../../Makefile.modules


