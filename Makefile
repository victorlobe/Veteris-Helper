export THEOS ?= $(HOME)/theos
export ARCHS = armv7 arm64
TARGET := iphone:7.1
INSTALL_TARGET_PROCESSES = SpringBoard

REPO_DEV ?= /Volumes/victor/Sites/repo-dev
PROJECT_NAME = VeterisHelper

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = VeterisHelper

VeterisHelper_FILES = Tweak.x
VeterisHelper_CFLAGS = -fobjc-arc
VeterisHelper_FRAMEWORKS = UIKit
VeterisHelper_PRIVATE_FRAMEWORKS = AppSupport

include $(THEOS_MAKE_PATH)/tweak.mk

# Force sequential execution (same as Veteris app Makefile).
.NOTPARALLEL: after-stage after-package dev-pipeline release-pipeline
MAKEFLAGS += -j1

ifeq ($(FINALPACKAGE),)
after-package:: dev-pipeline
else
after-package:: release-pipeline
endif

.PHONY: dev-pipeline release-pipeline

dev-pipeline:
	@echo "[📌] Starting Build on DEV Pipeline" 1>&2
	@script -q /dev/null /bin/bash -lc 'set -euo pipefail; \
		echo "[ℹ️ ] Locating latest .deb…"; \
		DEB="$$(ls -t "$(THEOS_PACKAGE_DIR)"/*.deb | head -1)"; \
		if [ -z "$$DEB" ] || [ ! -f "$$DEB" ]; then echo "[❌] No .deb found in $(THEOS_PACKAGE_DIR)"; exit 1; fi; \
		echo "[ℹ️ ] Found: $$DEB"; \
		BASE="$$(basename "$$DEB" .deb)"; TMP="$${BASE#*_}"; VERSION="$${TMP%_*}"; \
		echo "[ℹ️ ] Version: $$VERSION"; \
		# echo "[📦] Git commit…"; \
		# git add -A; \
		# if git commit -m "Build $$VERSION"; then echo "[✅] Commit successful"; else echo "[⚠️ ] Nothing to commit"; fi; \
		DEST="$(REPO_DEV)/debs"; \
		echo "[📂] Copy .deb → $$DEST"; \
		mkdir -p "$$DEST"; cp -v "$$DEB" "$$DEST/"; \
		echo "[⚙️ ] Run repo update…"; \
		cd "$(REPO_DEV)"; \
		if [ -f ./Update.sh ]; then /bin/bash ./Update.sh; \
		elif [ -f ./update.sh ]; then /bin/bash ./update.sh; \
		else echo "[⚠️ ] Warning: update script not found"; fi; \
		echo "[✅] Repo update finished"; \
		MSG="Built $$VERSION and updated repo"; \
		echo "[🔔] Notifying macOS…"; \
		/usr/bin/osascript -e "display notification \"$$MSG\" with title \"$(PROJECT_NAME) Build\" subtitle \"Deployment complete\"" \
		&& echo "[✅] Notification sent" || echo "[⚠️ ] Could not display notification"'

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
