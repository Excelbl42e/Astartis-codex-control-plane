defmodule AstartisWeb.Core.AstartisPort do
  @moduledoc """
  GenServer that owns the Port to the astartis_bridge C++ executable.

  Communication: newline-delimited JSON over stdio.
  - Outbound (to bridge): {"cmd": "...", "args": {...}}
  - Inbound  (from bridge): {"event": "...", "data": {...}}

  On every incoming message:
    1. Updates AstartisState with the latest snapshot data.
    2. Broadcasts {:telemetry, data} on PubSub topic "astartis:telemetry".

  If the bridge process exits, this GenServer stops and the supervisor
  restarts it (restart: :permanent).

  ## Elevation (Step 16)
  The bridge must be launched from an elevated terminal (Run as Administrator).
  It inherits the Administrator token automatically — no runas wrapper needed.
  Set config :astartis_web, :bridge_elevated to true to enable a warning when
  the bridge reports elevated=false at startup.
  """

  use GenServer
  require Logger

  @pubsub AstartisWeb.PubSub
  @topic  "astartis:telemetry"

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Send a command map to the bridge. Fire-and-forget."
  def send_command(cmd_map) when is_map(cmd_map) do
    if Process.whereis(__MODULE__) do
      GenServer.cast(__MODULE__, {:send, cmd_map})
    else
      {:error, :bridge_not_running}
    end
  end

  def running? do
    Process.whereis(__MODULE__) != nil
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    path = bridge_path()
    Logger.info("[AstartisPort] Opening bridge: #{path}")
    port = open_port(path)
    {:ok, %{port: port, buffer: ""}}
  end

  @impl true
  def handle_cast({:send, cmd_map}, state) do
    line = Jason.encode!(cmd_map) <> "\n"
    accepted = Port.command(state.port, line)
    Logger.debug("[AstartisPort] sent command=#{cmd_map["cmd"] || "unknown"} accepted=#{inspect(accepted)}")
    {:noreply, state}
  end

  @impl true
  def handle_info({port, {:data, {:eol, line}}}, %{port: port} = state) do
    full_line = state.buffer <> line
    state = %{state | buffer: ""}

    case Jason.decode(full_line) do
      {:ok, msg} ->
        handle_bridge_message(msg)
      {:error, reason} ->
        Logger.warning("[AstartisPort] JSON parse error: #{inspect(reason)} line=#{full_line}")
    end
    {:noreply, state}
  end

  def handle_info({port, {:data, {:noeol, chunk}}}, %{port: port} = state) do
    # Accumulate partial lines (shouldn't happen with {:line,...} but be safe)
    {:noreply, %{state | buffer: state.buffer <> chunk}}
  end

  def handle_info({port, {:exit_status, code}}, %{port: port} = state) do
    Logger.warning("[AstartisPort] Bridge exited with code #{code}, supervisor will restart")
    {:stop, :normal, state}
  end

  def handle_info({port, :closed}, %{port: port} = state) do
    Logger.warning("[AstartisPort] Bridge port closed")
    {:stop, :normal, state}
  end

  def handle_info(msg, state) do
    Logger.debug("[AstartisPort] Unhandled: #{inspect(msg)}")
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp handle_bridge_message(%{"event" => "ready", "data" => data}) do
    # ST-2 elevation gate: log elevation status; warn if expected but absent
    elevated = Map.get(data, "elevated", false)
    Logger.info("[AstartisPort] Bridge elevated: #{elevated}")
    if Application.get_env(:astartis_web, :bridge_elevated, false) and not elevated do
      Logger.warning("""
      [AstartisPort] WARNING: bridge_elevated is true in config but bridge \
      reports elevated=false. Step 16 netsh calls will fail with access-denied. \
      Start Phoenix from an elevated terminal (Run as Administrator).
      """)
    end
    AstartisWeb.Core.AstartisState.put(data)
    # Cache adapters before a browser connects so the capture picker is useful
    # on the first rendered dashboard frame as well.
    send_command(%{"cmd" => "packet_capture_list_adapters", "args" => %{}})
    # Policy zones are static local configuration, not a wireless scan. Cache
    # them before a dashboard subscribes so a fresh workspace is complete.
    send_command(%{"cmd" => "network_get_ssids", "args" => %{}})
    Phoenix.PubSub.broadcast(@pubsub, @topic, {:telemetry, "ready", data})
  end

  defp handle_bridge_message(%{"event" => event, "data" => data}) do
    if String.starts_with?(event, "packet_capture") do
      Logger.debug("[AstartisPort] received bridge event=#{event}")
    end

    # The native bridge includes the 77-agent status array in every 500 ms
    # tick. Agent state is also emitted explicitly by `agent_status_update`,
    # so rebroadcasting the same full fleet twice a second only makes the
    # LiveView payload and browser reconciliation unnecessarily expensive.
    # Keep status records in ETS when they actually change; send lightweight
    # posture ticks to connected dashboards in between.
    state_data = if event == "tick", do: Map.delete(data, "agent_statuses"), else: data
    broadcast_data = if event == "tick", do: Map.delete(data, "agent_statuses"), else: data

    # Update ETS state cache on every tick or snapshot
    if event in ["tick", "snapshot", "packet_capture_status", "agent_status_update"] do
      AstartisWeb.Core.AstartisState.put(state_data)
    end

    if event == "packet_capture_adapters" do
      current = AstartisWeb.Core.AstartisState.get()
      AstartisWeb.Core.AstartisState.put(
        Map.put(current, "capture_adapters", data["adapters"] || [])
      )
    end

    if event == "network_ssids" do
      current = AstartisWeb.Core.AstartisState.get()
      AstartisWeb.Core.AstartisState.put(
        Map.put(current, "network_ssids", data["ssids"] || [])
      )
    end

    # Chaos window events also update the K value in state
    if event == "chaos_window" do
      current = AstartisWeb.Core.AstartisState.get()
      history = Map.get(current, "chaos_history", [])
      new_history = Enum.take(history ++ [data["K"]], -50)
      AstartisWeb.Core.AstartisState.put(
        Map.merge(current, %{
          "chaos_K"        => data["K"],
          "chaos_anomalous"=> data["anomalous"],
          "chaos_history"  => new_history
        })
      )
    end

    # Step 17: unlock_vote_result — update state so tick snapshot stays in sync
    if event == "unlock_vote_result" do
      if data["unlocked"] do
        Logger.info("[AstartisPort] Unlock protocol: threshold reached — WORM unlocked")
      end
    end

    # ST-6: scan_quarantine_result — log and let LiveView broadcast handle display
    if event == "scan_quarantine_result" do
      Logger.info("[AstartisPort] Scan/quarantine result: status=#{data["status"]} " <>
                  "virus=#{data["virus_name"]} quarantined=#{data["quarantined"]}")
    end

    # ST-6: RULE-05 firewall candidate — auto-trigger block_ip if source_ip
    # is non-empty and not already handled. The rule engine keeps authority;
    # this is the Elixir-side execution of the decision already made in C++.
    if event == "rule05_firewall_candidate" do
      source_ip = data["source_ip"] || ""
      if source_ip != "" do
        Logger.warning("[AstartisPort] RULE-05 firewall candidate: K=#{data["K"]} ip=#{source_ip}")
        send_command(%{"cmd" => "block_ip", "args" => %{"ip" => source_ip, "ttl_s" => 900}})
      else
        Logger.info("[AstartisPort] RULE-05 candidate fired (no source_ip in synthetic mode)")
      end
    end

    # Broadcast everything to LiveView subscribers
    Phoenix.PubSub.broadcast(@pubsub, @topic, {:telemetry, event, broadcast_data})
  end

  defp handle_bridge_message(%{"event" => event}) do
    Phoenix.PubSub.broadcast(@pubsub, @topic, {:telemetry, event, %{}})
  end

  defp handle_bridge_message(other) do
    Logger.debug("[AstartisPort] Unexpected message shape: #{inspect(other)}")
  end

  defp open_port(path) do
    # Step 16: elevation is achieved by starting Phoenix from an elevated
    # terminal (Run as Administrator). The bridge inherits the token.
    # The :bridge_elevated flag in config now means "expect elevated=true
    # in the ready event and warn loudly if not" — NOT a runas wrapper.
    Port.open(
      {:spawn_executable, path},
      [:binary, :exit_status, {:line, 65_536}]
    )
  end

  defp bridge_path do
    # Priority order:
    # 1. ASTARTIS_BRIDGE_PATH environment variable
    # 2. Application config :bridge_path
    # 3. Relative default from this app's priv dir

    System.get_env("ASTARTIS_BRIDGE_PATH") ||
      Application.get_env(:astartis_web, :bridge_path) ||
      default_bridge_path()
  end

  defp default_bridge_path do
    # Relative to the astartis_web app directory. The maintained local Windows
    # build is build-vs18-pathfix; use it by default so dashboard controls and
    # the native bridge always come from the same current build.
    app_dir = :code.priv_dir(:astartis_web) |> to_string()
    # priv_dir is  .../astartis_web/_build/dev/lib/astartis_web/priv
    # Go up 6 levels to reach the repository root, then the maintained bridge build.
    Path.join([app_dir, "..", "..", "..", "..", "..", "..",
               "astartis", "build-vs18-pathfix", "Release", "astartis_bridge.exe"])
    |> Path.expand()
  end
end
