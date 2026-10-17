# Rules applied to apps that depend on this plugin.
# WireGuardRuntime reads these private members by reflection to stop a tunnel that is owned
# by another GoBackend instance in the same process, and the tunnel AAR ships no rules.
-keep class com.wireguard.android.backend.** { *; }
-keep class com.wireguard.config.** { *; }
-keep class com.wireguard.crypto.** { *; }
-keep class billion.group.wireguard_flutter.** { *; }
