################################################################################
#
# phantowd-code-hash
#
################################################################################

PHANTOWD_CODE_HASH_VERSION = 0.1.0
PHANTOWD_CODE_HASH_SITE = $(BR2_EXTERNAL_PHANTOWD_EX4_PATH)/src/phantowd-code-hash
PHANTOWD_CODE_HASH_SITE_METHOD = local
PHANTOWD_CODE_HASH_LICENSE = Apache-2.0, LGPL-3.0+
PHANTOWD_CODE_HASH_LICENSE_FILES = LICENSE COPYING.LESSERv3 COPYINGv3
PHANTOWD_CODE_HASH_DEPENDENCIES = nettle

define PHANTOWD_CODE_HASH_USERS
	phantowd-hash 59999 phantowd-hash 59999 * - /bin/false - Fixed read-only runtime hash worker
endef

# Recompile only these unmodified upstream C units. Never consume cached .o
# files or enable static libraries/Cgo globally. Nettle's configured headers
# and staging headers come from the same pinned Buildroot dependency.
define PHANTOWD_CODE_HASH_BUILD_CMDS
	$(INSTALL) -m 0644 $(BR2_EXTERNAL_PHANTOWD_EX4_PATH)/LICENSE $(@D)/LICENSE
	$(INSTALL) -m 0644 $(NETTLE_DIR)/COPYING.LESSERv3 $(NETTLE_DIR)/COPYINGv3 $(@D)/
	for name in sha256 sha256-compress-n write-be32; do \
		$(TARGET_CC) $(TARGET_CFLAGS) -g0 -DHAVE_CONFIG_H -I$(NETTLE_DIR) \
			-ffile-prefix-map=$(NETTLE_DIR)=nettle \
			-c $(NETTLE_DIR)/$$name.c -o $(@D)/$$name.o || exit 1; \
	done
	$(TARGET_CC) $(TARGET_CFLAGS) -g0 -std=c11 -Wall -Wextra -Werror \
		-fstack-protector-strong -ffile-prefix-map=$(@D)=. \
		$(@D)/main.c $(@D)/sha256.o $(@D)/sha256-compress-n.o $(@D)/write-be32.o \
		$(TARGET_LDFLAGS) -static -Wl,-z,relro,-z,now -o $(@D)/phantowd-code-hash
endef

define PHANTOWD_CODE_HASH_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/phantowd-code-hash $(TARGET_DIR)/usr/sbin/phantowd-code-hash
	for name in LICENSE COPYING.LESSERv3 COPYINGv3; do \
		$(INSTALL) -D -m 0644 $(@D)/$$name \
			$(TARGET_DIR)/usr/share/licenses/phantowd-code-hash/$$name || exit 1; \
	done
endef

$(eval $(generic-package))
