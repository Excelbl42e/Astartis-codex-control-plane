import Config

# ---------------------------------------------------------------------------
# astartis_bridge executable path (Step 15 — Port target)
#
# Resolution order:
#   1. ASTARTIS_BRIDGE_PATH environment variable  (highest priority)
#   2. This runtime config value
#   3. AstartisPort.default_bridge_path/0 (relative walk from priv dir)
#
# The relative default assumes astartis_web/ and astartis/ are sibling
# directories under the same repository root. Works on any machine where
# the project layout matches.
#
# Step 16 note: set bridge_elevated: true here when netsh calls are needed
# (real firewall rules require an elevated process). The Port supervisor
# reads this flag and wraps the launch in `cmd /c runas /trustlevel:0x20000`
# before spawning the bridge. Default is false (demo mode).
# ---------------------------------------------------------------------------

bridge_path =
  System.get_env("ASTARTIS_BRIDGE_PATH") ||
    Path.expand(
      Path.join([
        __DIR__,                                      # astartis_web/config/
        "..", "..",                                   # -> repository root
        "astartis", "build-vs18-pathfix", "Release", "astartis_bridge.exe"
      ])
    )

config :astartis_web,
  bridge_path: bridge_path,
  bridge_elevated: System.get_env("ASTARTIS_BRIDGE_ELEVATED", "false") == "true"
