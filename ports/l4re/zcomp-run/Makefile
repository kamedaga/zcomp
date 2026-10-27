PKGDIR ?= .
L4DIR ?= $(error L4DIRに公式L4Reソースの絶対パスを指定してください)
ZCOMP_DIR ?= $(abspath $(PKGDIR)/../../..)
ZYDIS_DIR ?= $(ZCOMP_DIR)/build/_deps/zydis-src

TARGET = zcomp-run
SYSTEMS = amd64-l4f
SRC_CC = main.cc state.cc memory.cc mappings.cc loader.cc capabilities.cc bootstrap.cc \
         task.cc linux/dispatch.cc linux/files.cc linux/mmap.cc linux/tls.cc linux/fork.cc \
         linux/lifecycle.cc linux/threads.cc linux/futex.cc linux/signals.cc
SRC_C = elf_image.c scan.c Decoder.c DecoderData.c SharedData.c Register.c
SRC_S = entry.S
REQUIRES_LIBS = l4re-util libstdc++ libpthread

# Linux用に構築したデコーダを流用せず、同じソースをL4Re向けにコンパイルする。
vpath %.c $(ZCOMP_DIR)/src $(ZYDIS_DIR)/src
PRIVATE_INCDIR = $(ZCOMP_DIR)/src $(ZYDIS_DIR)/include $(ZYDIS_DIR)/src \
                 $(ZYDIS_DIR)/dependencies/zycore/include
DEFINES += -DZYDIS_STATIC_BUILD -DZYAN_STATIC_BUILD -DZYDIS_MINIMAL_MODE \
           -DZYDIS_DISABLE_ENCODER -DZYDIS_DISABLE_FORMATTER
# 実行時に触れる拡張状態を限定し、Linux側のred zoneをランタイム自身は使わない。
CXXFLAGS += -std=c++17 -Wall -Wextra -Werror -mgeneral-regs-only \
            -mno-red-zone -fno-exceptions -fno-rtti -fno-stack-protector -fcf-protection=none
CFLAGS += -mno-red-zone -fno-stack-protector -fcf-protection=none
# 通常のLinux非PIE ELFが使う0x400000を、起動プログラムが占有しないため。
LDFLAGS += -Ttext-segment=0x10000000
include $(L4DIR)/mk/prog.mk
