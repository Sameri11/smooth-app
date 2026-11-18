"""Build jni with the generated package contract and verbose native commands.

Read CMake.log from the APK's transitioned CMake action, not a separately
configured log target. Package Recipe contributions may change native input
ordering; compare native entries by name and bytes.
"""

load("@rules_android//rules:rules.bzl", "android_library")
load(
    "@rules_flutter_android//flutter:composition.bzl",
    "android_native_files",
    "flutter_build_config",
)
load("@rules_flutter_android//flutter:defs.bzl", "flutter_native_contribution")
load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

_LIBRARIES = ["libdartjni.so"]

# The generator passes str(Label("@androidndk_cmake//:ndk_source_properties")) from
# inside rules_flutter_android. This consumer's MODULE.bazel pins androidndk_cmake
# through the same android_ndk extension, so the label resolves here too.
_NDK_SOURCE_PROPERTIES = str(Label("@androidndk_cmake//:ndk_source_properties"))

def _native_for_abi(name, abi, api_level):
    cmake_name = "{}_native_{}".format(name, abi)
    cmake(
        name = cmake_name,
        lib_source = ":{}_native_srcs".format(name),
        build_data = [_NDK_SOURCE_PROPERTIES],
        working_directory = "android/../src",
        cache_entries = {
            # An NDK cache entry suppresses rules_foreign_cc's STL-free crosstool.
            "CMAKE_TOOLCHAIN_FILE": "$$(dirname $$(realpath $$EXT_BUILD_ROOT$$/$(execpath {ndk})))/build/cmake/android.toolchain.cmake".format(ndk = _NDK_SOURCE_PROPERTIES),
            "ANDROID_ABI": abi,
            # Stock debug APK builds jni as CMake Debug (-g, no -O). foreign_cc
            # would default to Release under fastbuild.
            "CMAKE_BUILD_TYPE": "Debug",
            # Stock has empty CMAKE_C_FLAGS/CMAKE_CXX_FLAGS. An explicit empty
            # value drops the Bazel toolchain flags merged into them by rules_foreign_cc.
            "CMAKE_C_FLAGS": "",
            # Map the sandbox execroot out of DWARF and __FILE__ so output bytes
            # do not depend on the output base or sandbox ordinal.
            "CMAKE_C_FLAGS_DEBUG": "-g -fno-limit-debug-info -ffile-prefix-map=$$EXT_BUILD_ROOT$$=.",
            "CMAKE_CXX_FLAGS": "",
            "ANDROID_PLATFORM": "android-{}".format(api_level),
            # Use the NDK's link defaults, not the Bazel toolchain's API/strip flags.
            # jni's CMake target supplies the 16 KB maximum page size.
            "CMAKE_SHARED_LINKER_FLAGS": "",
        },
        generate_args = ["-GNinja"],
        # Matches the displayed build command; single-config Ninja ignores --config.
        configuration = "Debug",
        # Keep executed commands in the APK action's CMake.log.
        build_args = ["--verbose"],
        # These projects have no install() rule, so copy their declared outputs to
        # the directory rules_foreign_cc collects when installation is disabled.
        install = False,
        out_shared_libs = _LIBRARIES,
        postfix_script = "mkdir -p $$INSTALLDIR/lib && cp {} $$INSTALLDIR/lib/".format(" ".join(_LIBRARIES)),
    )
    android_native_files(
        name = "{}_native_files_{}".format(name, abi),
        src = [":" + cmake_name],
        abi = abi,
    )

def jni_recipe(name, info):
    """Build the jni package: Java module and CMake native libraries per ABI.

    Args:
        name: Generated plugin target name.
        info: Resolved plugin sources, dependencies and requested ABIs.
    """
    native.filegroup(
        name = name + "_native_srcs",
        srcs = info.all_files,
    )
    for abi in info.abis:
        _native_for_abi(name, abi, info.api_level)

    flutter_build_config(
        name = "build_config",
        package_name = info.namespace,
        fields = [],
    )
    android_library(
        name = name,
        srcs = info.android_srcs + [
            f
            for f in info.all_files
            if f.startswith("java/src/main/java/") and f.endswith(".java")
        ] + [":build_config"],
        manifest = info.android_manifest,
        custom_package = info.namespace,
        exports_manifest = True,
        resource_files = info.resource_files,
        proguard_specs = ["android/consumer-rules.pro"],
        deps = [info.embedding] + info.plugin_deps + info.coordinates,
    )

    flutter_native_contribution(
        name = name + "_flutter_native",
        libraries = {abi: ":{}_native_files_{}".format(name, abi) for abi in info.abis},
    )
