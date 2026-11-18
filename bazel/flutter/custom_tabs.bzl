"""Custom Tabs plugin recipe preserving its stock Kotlin module name."""

load("@rules_flutter_android//flutter:defs.bzl", "flutter_native_contribution")
load("@rules_kotlin//kotlin:android.bzl", "kt_android_library")

def flutter_custom_tabs_android_recipe(name, info):
    """Build plugin sources with the stock debug Kotlin module name."""
    kt_android_library(
        name = name,
        srcs = info.android_srcs,
        manifest = info.android_manifest,
        custom_package = info.namespace,
        exports_manifest = 1,
        resource_files = info.resource_files,
        module_name = "flutter_custom_tabs_android_debug",
        deps = [info.embedding] + info.plugin_deps + info.coordinates,
    )
    flutter_native_contribution(name = name + "_flutter_native", empty = True)
