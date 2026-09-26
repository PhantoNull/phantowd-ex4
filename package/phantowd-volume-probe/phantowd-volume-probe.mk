################################################################################
# phantowd-volume-probe
################################################################################

PHANTOWD_VOLUME_PROBE_VERSION = 0.1.0
PHANTOWD_VOLUME_PROBE_SITE = $(BR2_EXTERNAL_PHANTOWD_EX4_PATH)/src/phantowd-volume-probe
PHANTOWD_VOLUME_PROBE_SITE_METHOD = local
PHANTOWD_VOLUME_PROBE_LICENSE = Apache-2.0
PHANTOWD_VOLUME_PROBE_LICENSE_FILES = LICENSE
PHANTOWD_VOLUME_PROBE_DEPENDENCIES = util-linux

# Buildroot owns _FORTIFY_SOURCE through TARGET_CFLAGS. Redefining it here
# conflicts with its configured level and breaks compilation under -Werror.
define PHANTOWD_VOLUME_PROBE_BUILD_CMDS
	$(INSTALL) -m 0644 $(BR2_EXTERNAL_PHANTOWD_EX4_PATH)/LICENSE $(@D)/LICENSE
	$(TARGET_CC) $(TARGET_CFLAGS) -std=c11 -Wall -Wextra -Werror \
		-fstack-protector-strong \
		$(@D)/probe.c $(TARGET_LDFLAGS) -Wl,-z,relro,-z,now \
		-lblkid -o $(@D)/phantowd-volume-probe
endef

define PHANTOWD_VOLUME_PROBE_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/phantowd-volume-probe \
		$(TARGET_DIR)/usr/libexec/phantowd-volume-probe
	$(INSTALL) -D -m 0644 $(@D)/LICENSE \
		$(TARGET_DIR)/usr/share/licenses/phantowd-volume-probe/LICENSE
endef

$(eval $(generic-package))
