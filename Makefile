export THEOS ?= $(HOME)/theos
HELPER_DEVELOPER_DIR ?= /Applications/Xcode 26.6.app/Contents/Developer
export THEOS_PLATFORM_SDK_ROOT := $(HELPER_DEVELOPER_DIR)
empty :=
space := $(empty) $(empty)
PINNED_TOOLCHAIN_BIN := $(subst $(space),\ ,$(HELPER_DEVELOPER_DIR))/Toolchains/XcodeDefault.xctoolchain/usr/bin
ifeq ($(wildcard $(PINNED_TOOLCHAIN_BIN)/clang),)
$(error Xcode 26.6 not found at $(HELPER_DEVELOPER_DIR); set HELPER_DEVELOPER_DIR to an Xcode with ld-1267)
endif
export TARGET_CC := $(PINNED_TOOLCHAIN_BIN)/clang
export TARGET_CXX := $(PINNED_TOOLCHAIN_BIN)/clang++
export TARGET_LD := $(PINNED_TOOLCHAIN_BIN)/clang
export TARGET_LIPO := $(PINNED_TOOLCHAIN_BIN)/lipo
export TARGET_CODESIGN_ALLOCATE := $(PINNED_TOOLCHAIN_BIN)/codesign_allocate
export TARGET_DSYMUTIL := $(PINNED_TOOLCHAIN_BIN)/dsymutil
export TARGET_STRIP := $(PINNED_TOOLCHAIN_BIN)/strip
export ARCHS = armv7 arm64
TARGET := iphone:7.1:5.0
INSTALL_TARGET_PROCESSES = SpringBoard

REPO_DEV ?= /Volumes/victor/Sites/repo-dev
GIT_ROOT ?= $(abspath ..)
DEPLOY_SCRIPT ?= $(GIT_ROOT)/Scripts/repo-dev-deploy.sh
PROJECT_NAME = VeterisHelper

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = VeterisHelper
TWEAK_NAME += VeterisAuth

AUTH_CORE ?= $(GIT_ROOT)/VeterisAuthCore
AUTH_MBEDTLS ?= $(GIT_ROOT)/VeterisApp/deps/mbedtls
-include $(CURDIR)/Auth/local.mk
AUTH_KIND ?= $(if $(FINALPACKAGE),release,dev)
ifneq ($(FINALPACKAGE),)
ifneq ($(AUTH_KIND),release)
$(error Release packages require AUTH_KIND=release)
endif
endif
AUTH_SECRETS_DIR ?= $(HOME)/.veteris-secrets/auth
AUTH_PUBLIC_KEYS ?= $(CURDIR)/Auth/server-public-keys.txt
AUTH_BUILD_DIR := $(CURDIR)/.theos/auth/$(AUTH_KIND)
AUTH_VERSION := $(shell sed -n 's/^Version: //p' $(CURDIR)/control)
AUTH_MODULES := bignum ecp ecp_curves chacha20 poly1305 chachapoly sha256 md hkdf platform_util constant_time hmac_drbg
AUTH_ATTEST := $(AUTH_CORE)/src/vauth_attest.c
VeterisAuth_ARCHS = armv7
VeterisAuth_FILES = VeterisAuth.x $(AUTH_CORE)/src/vauth.c $(AUTH_CORE)/src/vauth_attest_message.c $(AUTH_ATTEST) $(addprefix $(AUTH_MBEDTLS)/library/,$(addsuffix .c,$(AUTH_MODULES)))
VeterisAuth_CFLAGS = -fobjc-arc -fvisibility=hidden -I$(AUTH_CORE)/include -I$(AUTH_BUILD_DIR) -I$(AUTH_MBEDTLS)/include -I$(CURDIR)/Auth -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\"
VeterisAuth_FRAMEWORKS = Foundation Security

before-all:: auth-prepare
auth-prepare:
	@python3 "$(CURDIR)/Auth/prepare_build.py" --kind "$(AUTH_KIND)" --secrets-dir "$(AUTH_SECRETS_DIR)" --public-keys "$(AUTH_PUBLIC_KEYS)" --output "$(AUTH_BUILD_DIR)" --version "$(AUTH_VERSION)" $(AUTH_PREPARE_FLAGS)

VeterisHelper_FILES = Tweak.x
VeterisHelper_CFLAGS = -fobjc-arc
VeterisHelper_FRAMEWORKS = UIKit
VeterisHelper_PRIVATE_FRAMEWORKS = AppSupport

include $(THEOS_MAKE_PATH)/tweak.mk

# Force sequential execution (same as Veteris app Makefile).
.NOTPARALLEL: after-stage after-package archive-build commit-archive dev-pipeline release-pipeline remove-git-lock
MAKEFLAGS += -j1

after-all:: check-thumb-bits
after-all:: check-auth-imports
after-all:: check-helper-imports

ifneq ($(LOCAL_PACKAGE),1)
before-package:: remove-git-lock
ifeq ($(FINALPACKAGE),)
after-package:: dev-pipeline
else
before-package:: release-overwrite-check
after-package:: commit-archive
after-package:: release-pipeline
endif
endif

after-stage::
	@$(TARGET_STRIP) -x "$(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/VeterisAuth.dylib"
	@$(TARGET_CODESIGN) $(TARGET_CODESIGN_FLAGS) "$(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/VeterisAuth.dylib"

.PHONY: dev-pipeline release-pipeline release-overwrite-check remove-git-lock archive-build commit-archive check-thumb-bits check-auth-imports check-helper-imports auth-prepare

check-auth-imports:
	@if nm -u "$(THEOS_OBJ_DIR)/VeterisAuth.dylib" | grep -qE '_OBJC_(META)?CLASS_\$$_NSObject$$'; then \
		echo "[❌] VeterisAuth.dylib imports NSObject; it would not load on iOS 5" 1>&2; exit 1; \
	else echo "[✅] VeterisAuth.dylib has no NSObject import (loads on iOS 5)"; fi

check-helper-imports:
	@test -f "$(THEOS_OBJ_DIR)/VeterisHelper.dylib" || { echo "[❌] VeterisHelper.dylib not found" 1>&2; exit 1; }
	@if nm -m -u -arch armv7 "$(THEOS_OBJ_DIR)/VeterisHelper.dylib" | grep -qE '_OBJC_(META)?CLASS_\$$_NSObject \(from libobjc\)'; then \
		echo "[❌] VeterisHelper.dylib imports NSObject from libobjc; it would not load on iOS 5" 1>&2; exit 1; \
	else echo "[✅] VeterisHelper.dylib does not import NSObject from libobjc (loads on iOS 5)"; fi

check-thumb-bits:
	@/bin/bash "$(CURDIR)/check-thumb-bits.sh" "$(THEOS_OBJ_DIR)/VeterisHelper.dylib"
	@/bin/bash "$(CURDIR)/check-thumb-bits.sh" "$(THEOS_OBJ_DIR)/VeterisAuth.dylib"

archive-build:
	@echo "[🗃️ ] Archive build artifacts…" 1>&2
	@FINALPACKAGE="$(FINALPACKAGE)" HELPER_OBJ_DIR="$(THEOS_OBJ_DIR)" /bin/bash "$(CURDIR)/archive-build.sh"

commit-archive: archive-build
	@FINALPACKAGE="$(FINALPACKAGE)" /bin/bash "$(CURDIR)/commit-archive.sh"

remove-git-lock:
	@rm -rf "$(GIT_ROOT)/.git/index.lock"

release-overwrite-check:
	@/bin/bash -lc 'set -euo pipefail; \
		CONTROL="$(CURDIR)/control"; \
		PKG="$$(grep -i "^Package:" "$$CONTROL" | cut -d: -f2- | tr -d " \r\n\t")"; \
		VER="$$(grep -i "^Version:" "$$CONTROL" | cut -d: -f2- | tr -d " \r\n\t")"; \
		PKG_DIR="$(THEOS_PACKAGE_DIR)"; \
		[ -n "$$PKG_DIR" ] || PKG_DIR="$(CURDIR)/packages"; \
		OUT="$$PKG_DIR/$${PKG}_$${VER}_iphoneos-arm.deb"; \
		if [ -e "$$OUT" ]; then \
			echo "[⚠️ ] Release package version $$VER already exists:"; \
			echo "      $$OUT"; \
			printf "Overwrite this FINALPACKAGE build? [y/N] "; \
			read -r answer; \
			case "$$answer" in y|Y|yes|YES) echo "[ℹ️ ] Continuing and overwriting $$VER";; *) echo "[❌] Aborted before overwriting release package $$VER"; exit 1;; esac; \
		fi'

dev-pipeline:
	@echo "[📌] Starting Build on DEV Pipeline" 1>&2
	@THEOS_PACKAGE_DIR="$(THEOS_PACKAGE_DIR)" REPO_DEV="$(REPO_DEV)" DEPLOY_SCRIPT="$(DEPLOY_SCRIPT)" PROJECT_NAME="$(PROJECT_NAME)" /bin/bash "$(CURDIR)/dev-pipeline.sh"

release-pipeline:
	@echo "[📌] Starting Build on RELEASE Pipeline" 1>&2
	@script -q /dev/null /bin/bash -lc 'set -euo pipefail; \
		DEB="$$(ls -t "$(THEOS_PACKAGE_DIR)"/*.deb | head -1)"; \
		if [ -z "$$DEB" ] || [ ! -f "$$DEB" ]; then echo "[❌] No .deb found in $(THEOS_PACKAGE_DIR)"; exit 1; fi; \
		BASE="$$(basename "$$DEB" .deb)"; TMP="$${BASE#*_}"; VER="$${TMP%_*}"; \
		echo "[🚀 RELEASE] Built $$DEB (Version: $$VER)"; \
		echo "[ℹ️ ] (Release mode: no deploy)"; \
		# git add -A || true; \
		# if git commit -m "Release $$VER"; then \
		# 	echo "[✅] Git commit: Release $$VER"; \
		# else \
		# 	echo "[⚠️ ] Nothing to commit"; \
		# fi; \
		:'
