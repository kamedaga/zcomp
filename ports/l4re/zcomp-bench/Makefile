PKGDIR ?= .
L4DIR ?= $(error L4DIRに公式L4Reソースの絶対パスを指定してください)
ZCOMP_DIR ?= $(abspath $(PKGDIR)/../../..)
TARGET = zcomp-bench
SYSTEMS = amd64-l4f
SRC_CC = main.cc
REQUIRES_LIBS = l4re-util libstdc++ libpthread
PRIVATE_INCDIR = $(ZCOMP_DIR)/ports/l4re/zcomp-bench
CXXFLAGS += -std=c++17 -Wall -Wextra -Werror -mno-red-zone
include $(L4DIR)/mk/prog.mk
