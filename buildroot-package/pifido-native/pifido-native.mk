################################################################################
# pifido-native
################################################################################

PIFIDO_NATIVE_VERSION = 1.0
PIFIDO_NATIVE_SITE = $(TOPDIR)/../native
PIFIDO_NATIVE_SITE_METHOD = local
PIFIDO_NATIVE_LICENSE = MIT
PIFIDO_NATIVE_DEPENDENCIES = openssl mbedtls

define PIFIDO_NATIVE_BUILD_CMDS
	$(TARGET_MAKE_ENV) $(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_CPPFLAGS) \
		-I$(@D) -o $(@D)/pifido-native \
		$(@D)/pifido_native.c $(@D)/store.c $(@D)/crypto.c \
		$(@D)/cbor.c $(@D)/ctap.c \
		$(TARGET_LDFLAGS) -lcrypto -lmbedcrypto
endef

define PIFIDO_NATIVE_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/pifido-native \
		$(TARGET_DIR)/usr/bin/pifido-native
endef

$(eval $(generic-package))
