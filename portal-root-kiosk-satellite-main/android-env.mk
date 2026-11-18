# Shared Android build paths. Explicit make variables take precedence, followed
# by the standard Android environment variables and per-user SDK location.
SDK ?= $(if $(ANDROID_SDK_ROOT),$(ANDROID_SDK_ROOT),$(if $(ANDROID_HOME),$(ANDROID_HOME),$(if $(wildcard $(HOME)/Android/Sdk),$(HOME)/Android/Sdk,$(HOME)/android-sdk)))
NDK ?= $(if $(ANDROID_NDK_HOME),$(ANDROID_NDK_HOME),$(if $(ANDROID_NDK_ROOT),$(ANDROID_NDK_ROOT),$(SDK)/ndk/28.2.13676358))
BUILD_TOOLS ?= $(SDK)/build-tools/37.0.0
ANDROID_JAR ?= $(SDK)/platforms/android-36/android.jar
D8 ?= $(BUILD_TOOLS)/d8
KEYSTORE ?= $(HOME)/.android/debug.keystore

# NDK prebuilt tag: the macOS NDK ships darwin-x86_64 toolchain binaries (run
# under Rosetta 2 on Apple Silicon); Linux uses linux-x86_64. Allow an explicit
# NDK_PREBUILT override for unusual layouts.
HOST_TAG := $(shell uname -s 2>/dev/null)
ifeq ($(HOST_TAG),Darwin)
NDK_PREBUILT ?= darwin-x86_64
else
NDK_PREBUILT ?= linux-x86_64
endif
TOOLCHAIN_DIR ?= $(NDK)/toolchains/llvm/prebuilt/$(NDK_PREBUILT)
