################################################################################
#
# FuzzUEr userspace proof of concepts
#
################################################################################

FUZZUER_POC_VERSION = 1.0.0
FUZZUER_POC_SITE = $(BR2_EXTERNAL_DIR)/fuzzuer_poc
FUZZUER_POC_SITE_METHOD = local

define FUZZUER_POC_BUILD_CMDS
    gcc $(@D)/source/fuzzuer_poc.c $(@D)/source/userspace_helpers.c $(@D)/source/userspace_harnesses.c -o $(@D)/fuzzuer_poc
endef

define FUZZUER_POC_INSTALL_TARGET_CMDS
    $(INSTALL) -D -m 0755 $(@D)/fuzzuer_poc $(TARGET_DIR)/usr/bin
endef

$(eval $(generic-package))