# Kernel module sysup
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

PKG_NAME:=sysup
PKG_RELEASE:=1

define KernelPackage/sysup
	SUBMENU:=Other modules
	TITLE:=Support Module for sysup
	FILES:=$(PKG_BUILD_DIR)/sysup.$(LINUX_KMOD_SUFFIX)
	DEPENDS:= +kmod-crypto-hash +kmod-crypto-md5 +kmod-crypto-cbc +kmod-crypto-aes +kmod-crypto-ocf +kmod-ipt-nat
	AUTOLOAD:=$(call AutoLoad,91,sysup)
	MENU:=1
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

SYSUP_TIME:=$(call qstrip,$(CONFIG_SYSUP_TIME))
SYSUP_TIME:=$(if $(SYSUP_TIME),$(SYSUP_TIME),3600)
EXTRA_CFLAGS+= -D SYSUP_TIME=$(SYSUP_TIME)

SYSUP_INTERVAL:=$(call qstrip,$(CONFIG_SYSUP_INTERVAL))
SYSUP_INTERVAL:=$(if $(SYSUP_INTERVAL),$(SYSUP_INTERVAL),300)
EXTRA_CFLAGS+= -D SYSUP_INTERVAL=$(SYSUP_INTERVAL)

SYSUP_LOG:=$(call qstrip,$(CONFIG_SYSUP_LOG))
SYSUP_LOG:=$(if $(SYSUP_LOG),$(SYSUP_LOG),n)
ifeq ($(SYSUP_LOG),n) 
EXTRA_CFLAGS+= -D VER_REL
endif

define Build/Compile
	$(MAKE) -C "$(PKG_BUILD_DIR)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	ARCH="$(LINUX_KARCH)" \
	SUBDIRS="$(PKG_BUILD_DIR)" \
	KERNELDIR="$(LINUX_DIR)" \
	CFLAGS="$(TARGET_CFLAGS)" \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)"\
	all
endef


define KernelPackage/sysup/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/sys
	$(INSTALL_DIR) $(1)/lib/modules/$(LINUX_VERSION)
	$(CP) $(PKG_BUILD_DIR)/sysup.$(LINUX_KMOD_SUFFIX) $(1)/lib/modules/$(LINUX_VERSION)
endef

define Package/kmod-sysup/config
	menu "Configuration"
		depends PACKAGE_kmod-sysup

	config SYSUP_TIME
		int "Time for updating rules (s)"
		default 3600

	config SYSUP_INTERVAL
		int "Throld  for updating rules (s)"
		default 300
		
	config SYSUP_LOG
		bool "Enable debug message"
		default n

	endmenu
endef
define Build/Install
endef

$(eval $(call KernelPackage,sysup))
