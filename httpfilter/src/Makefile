all:

KERNELDIR:=/usr/src/linux-source-3.2
SUBDIRS:=$(PWD)

obj-m := sysup.o
sysup-objs =    hellomain.o  pcre_compile.o pcre_config.o pcre_dfa_exec.o pcre_exec.o pcre_fullinfo.o pcre_get.o pcreposix.o \
                pcre_globals.o pcre_info.o pcre_maketables.o pcre_newline.o pcre_ord2utf8.o pcre_refcount.o pcre_study.o \
                pcre_tables.o pcre_try_flipped.o pcre_ucd.o pcre_valid_utf8.o pcre_version.o pcre_xclass.o pcre_chartables.o net_helper.o
hellomain.o: hellomain.c hellomain.h
all:
	$(MAKE) -C $(KERNELDIR) M=$(SUBDIRS) modules

clean:
	@rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

.PHONY: all