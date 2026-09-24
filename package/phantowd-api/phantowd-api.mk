################################################################################
#
# phantowd-api
#
################################################################################

PHANTOWD_API_VERSION = 0.1.0
PHANTOWD_API_SITE = $(BR2_EXTERNAL_PHANTOWD_EX4_PATH)/src/phantowd-api
PHANTOWD_API_SITE_METHOD = local
PHANTOWD_API_LICENSE = Apache-2.0, BSD-3-Clause
PHANTOWD_API_LICENSE_FILES = LICENSE Go-LICENSE Go-XCrypto-LICENSE Go-XSys-LICENSE
PHANTOWD_API_GOMOD = github.com/PhantoNull/phantowd-ex4/phantowd-api
PHANTOWD_API_GO_ENV = CGO_ENABLED=0
PHANTOWD_API_LDFLAGS = -s -w
PHANTOWD_API_USERS = phantowd -1 phantowd -1 * /nonexistent /bin/false - PhantoWD diagnostics
PHANTOWD_API_GO_LICENSE_DIR = $(if $(BR2_PACKAGE_HOST_GO_BIN),$(HOST_GO_BIN_DIR),$(HOST_GO_SRC_DIR))

define PHANTOWD_API_COPY_LICENSE
	$(INSTALL) -m 0644 $(BR2_EXTERNAL_PHANTOWD_EX4_PATH)/LICENSE $(@D)/LICENSE
	$(INSTALL) -m 0644 $(PHANTOWD_API_GO_LICENSE_DIR)/LICENSE $(@D)/Go-LICENSE
	$(INSTALL) -m 0644 $(BR2_EXTERNAL_PHANTOWD_EX4_PATH)/src/phantowd-api/vendor/golang.org/x/crypto/LICENSE $(@D)/Go-XCrypto-LICENSE
	$(INSTALL) -m 0644 $(BR2_EXTERNAL_PHANTOWD_EX4_PATH)/src/phantowd-api/vendor/golang.org/x/sys/LICENSE $(@D)/Go-XSys-LICENSE
endef
# Copy after compiler dependencies exist, including on a fresh parallel build.
PHANTOWD_API_PRE_BUILD_HOOKS += PHANTOWD_API_COPY_LICENSE

define PHANTOWD_API_INSTALL_LICENSES
	$(INSTALL) -D -m 0644 $(@D)/LICENSE \
		$(TARGET_DIR)/usr/share/licenses/phantowd-api/LICENSE
	$(INSTALL) -D -m 0644 $(@D)/Go-LICENSE \
		$(TARGET_DIR)/usr/share/licenses/phantowd-api/Go-LICENSE
	$(INSTALL) -D -m 0644 $(@D)/Go-XCrypto-LICENSE \
		$(TARGET_DIR)/usr/share/licenses/phantowd-api/Go-XCrypto-LICENSE
	$(INSTALL) -D -m 0644 $(@D)/Go-XSys-LICENSE \
		$(TARGET_DIR)/usr/share/licenses/phantowd-api/Go-XSys-LICENSE
endef
PHANTOWD_API_POST_INSTALL_TARGET_HOOKS += PHANTOWD_API_INSTALL_LICENSES

define PHANTOWD_API_INSTALL_INIT_SYSV
	$(INSTALL) -D -m 0755 $(PHANTOWD_API_PKGDIR)/S50phantowd-api \
		$(TARGET_DIR)/etc/init.d/S50phantowd-api
endef

$(eval $(golang-package))
