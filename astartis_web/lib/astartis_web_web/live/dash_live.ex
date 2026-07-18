defmodule AstartisWebWeb.DashLive do
  @moduledoc """
  Astartis v2.1 — OS-Grade Security Operations Center Dashboard.

  Full OS-desktop experience:
  - Astartis × Codex top bar with live status pills
  - Left app dock (9 apps: Network, Defense, Agents, Sandbox, Pipeline, NAC, Reports, Audit, Settings)
  - Main desktop area — switchable app windows
  - System Terminal — real-time event log with colour coding and filters
  - All v1 data + v2 Agent Swarm + NAC/ZT bridge commands
  """

  use AstartisWebWeb, :live_view
  alias AstartisWeb.Core.{AstartisState, DemoScript}

  @pass :two
  @pubsub AstartisWeb.PubSub
  @topic  "astartis:telemetry"
  @chaos_history_max 50

  # ---------------------------------------------------------------------------
  # Mount
  # ---------------------------------------------------------------------------

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(@pubsub, @topic)
      AstartisWeb.Core.AstartisPort.send_command(%{"cmd" => "get_snapshot", "args" => %{}})
      AstartisWeb.Core.AstartisPort.send_command(%{"cmd" => "agent_status", "args" => %{}})
      AstartisWeb.Core.AstartisPort.send_command(%{"cmd" => "network_get_ssids", "args" => %{}})
      AstartisWeb.Core.AstartisPort.send_command(%{"cmd" => "packet_capture_list_adapters", "args" => %{}})
      request_runtime_status()
    end

    state = AstartisState.get()

    {:ok,
     socket
     |> assign_state(state)
     |> assign(
          chaos_history:            state["chaos_history"] || [],
          active_tab:               "attack",
          attribution_techniques:   state["attribution_techniques"] || [],
          pass:                     @pass,
          demo_running:             false,
          last_scan_result:         nil,
          last_block_result:        nil,
          unlock_votes_collected:   0,
          unlock_threshold:         3,
          unlock_state:             "IDLE",
          unlock_approvers:         [],
          last_triage:              nil,
          veeam_lock_state:         "UNLOCKED",
          veeam_backup_count:       0,
          veeam_locked_at_ms:       0,
          veeam_integrity_checks:   0,
          veeam_locked_by_reason:   "",
          pipeline_stage:           nil,
          agent_statuses:           state["agent_statuses"] || [],
          agent_queue_depth:        state["agent_queue_depth"] || 0,
          packet_capture_running:   state["packet_capture_running"] || false,
          packet_capture_mode:      state["packet_capture_mode"] || "stopped",
          packet_capture_adapter:   state["packet_capture_adapter"] || "",
          packet_windows:           state["packet_windows"] || 0,
          packet_threat_score:      state["packet_threat_score"] || 0,
          packet_anomalous:         state["packet_anomalous"] || false,
          capture_adapters:         state["capture_adapters"] || [],
          capture_adapter_choice:   "",
          bridge_elevated:          state["elevated"],
          capture_action_state:     "idle",
          capture_error:            nil,
          capture_start_timer:      nil,
          dashboard_density:        "comfortable",
          evidence_window_label:    "Current session",
          terminal_dock_visible:    true,
          runtime_status:           nil,
          runtime_status_state:     "awaiting",
          last_agent_task_id:       nil,
          last_agent_result:        nil,
          # v2.1 new assigns
          active_app:               "overview",
          terminal_lines:           [],
          terminal_filters:         ~w(TERM PACKET RULE WORM AGENT AI AUDIT NAC ZT DECOY SANDBOX),
          nac_ssids:                state["network_ssids"] || [],
          nac_selected_ssid:        nil,
          nac_device_mac:           "aa:bb:cc:dd:ee:ff",
          nac_device_type:          "BYOD",
          nac_result:               nil,
          nac_step:                 0,
          zt_result:                nil,
          sandbox_selected:         nil,
          audit_blocks:             [],
          audit_selected:           nil,
          version_records:          [],
          version_selected:         nil,
          version_history:          [],
          terminal_cmd_output:      nil,
          show_about_modal:         false,
          show_worm_modal:          false
        )}
  end

  # ---------------------------------------------------------------------------
  # PubSub events
  # ---------------------------------------------------------------------------

  @impl true
  def handle_info({:telemetry, "tick", data}, socket) do
    history = update_chaos_history(socket.assigns.chaos_history, data["chaos_history"])
    # Keep posture current without appending two terminal rows per second.  The
    # previous terminal churn made an otherwise idle LiveView increasingly costly.
    {:noreply, socket |> assign_state(data) |> assign(chaos_history: history)}
  end

  def handle_info({:telemetry, "chaos_window", data}, socket) do
    history = (socket.assigns.chaos_history ++ [data["K"]]) |> Enum.take(-@chaos_history_max)
    socket = assign(socket, chaos_history: history, chaos_K: data["K"], chaos_anomalous: data["anomalous"])
    socket = push_event(socket, "packet_frame", %{entropy: data["K"] * 8.0, anomalous: data["anomalous"]})
    socket = push_terminal(socket, "PACKET", "entropy=#{Float.round(data["K"] * 8.0, 2)} K=#{Float.round(data["K"] + 0.0, 4)} anomalous=#{data["anomalous"]}")
    {:noreply, socket}
  end

  def handle_info({:telemetry, "packet_capture_status", data}, socket) do
    mode = data["packet_capture_mode"] || "stopped"
    socket = socket |> clear_capture_start_timer() |> assign_state(data)
    {:noreply,
     assign(socket,
       capture_action_state: if(data["packet_capture_running"], do: "running", else: "idle"),
       capture_error: if(mode == "synthetic", do: "Npcap could not open a usable adapter. Astartis is in synthetic demo mode, not live capture.", else: nil)
     )}
  end

  def handle_info({:telemetry, "packet_entropy_window", data}, socket) do
    socket = assign(socket,
      packet_windows: data["window_index"] + 1,
      packet_threat_score: data["threat_score"],
      packet_anomalous: data["anomalous"],
      packet_capture_adapter: data["adapter"],
      packet_capture_mode: data["mode"]
    )

    {:noreply,
     push_terminal(socket, "PACKET",
       "#{data["mode"]} capture window=#{data["window_index"]} entropy=#{Float.round((data["mean_entropy_bits"] || 0.0) + 0.0, 2)} score=#{data["threat_score"]}")}
  end

  def handle_info({:telemetry, "packet_capture_error", data}, socket) do
    socket = socket |> clear_capture_start_timer() |> assign(capture_action_state: "error", capture_error: data["message"])
    {:noreply, push_terminal(socket, "PACKET", "Capture error: #{data["message"]}")}
  end

  def handle_info(:capture_start_timeout, socket) do
    if socket.assigns.capture_action_state == "starting" do
      socket =
        socket
        |> clear_capture_start_timer()
        |> assign(
          capture_action_state: "error",
          capture_error: "Astartis did not receive a capture confirmation. Restart the dashboard and verify that the current bridge build is running."
        )

      {:noreply, push_terminal(socket, "PACKET", "Capture start timed out before the bridge confirmed an adapter")}
    else
      {:noreply, socket}
    end
  end

  def handle_info({:telemetry, "packet_capture_adapters", data}, socket) do
    adapters = data["adapters"] || []
    choice = socket.assigns.capture_adapter_choice || ""
    {:noreply, assign(socket, capture_adapters: adapters, capture_adapter_choice: choice)}
  end

  def handle_info({:telemetry, "unknown_cmd", data}, socket) do
    cmd = data["cmd"] || "unknown"
    socket = assign(socket, capture_action_state: "error", capture_error: "The bridge does not support #{cmd}. Restart Astartis so it uses the current bridge build.")
    {:noreply, push_terminal(socket, "AUDIT", "Bridge rejected command=#{cmd}")}
  end

  def handle_info({:telemetry, "worm_status", data}, socket) do
    socket = assign(socket, worm_locked: data["locked"], worm_reason: data["reason"] || "")
    socket = push_terminal(socket, "WORM", if(data["locked"], do: "LOCKED reason=#{data["reason"]}", else: "status=NORMAL"))
    {:noreply, socket}
  end

  def handle_info({:telemetry, "worm_trigger", data}, socket) do
    socket = assign(socket, worm_locked: true, worm_reason: data["reason"] || "triggered")
    socket = push_terminal(socket, "WORM", "Lockdown engaged — reason=#{data["reason"] || "rule"}")
    {:noreply, socket}
  end

  def handle_info({:telemetry, "signal_result", data}, socket) do
    socket = assign(socket, threat_tier: data["tier"], threat_tier_name: tier_name(data["tier"]))
    socket = push_terminal(socket, "RULE", "signal processed tier=#{tier_name(data["tier"])} score=#{data["score"] || "?"}")
    {:noreply, socket}
  end

  def handle_info({:telemetry, "attribution_report", data}, socket) do
    socket = assign(socket, attribution_techniques: data["techniques"] || [])
    n = length(data["techniques"] || [])
    socket = push_terminal(socket, "AUDIT", "attribution report — #{n} MITRE ATT&CK techniques mapped")
    {:noreply, socket}
  end

  def handle_info({:telemetry, "unlock_vote_result", data}, socket) do
    socket = assign(socket,
      unlock_votes_collected: data["votes_now"]    || socket.assigns.unlock_votes_collected,
      unlock_state:           data["unlock_state"] || socket.assigns.unlock_state
    )
    socket = push_terminal(socket, "WORM", "unlock vote — state=#{data["unlock_state"]} votes=#{data["votes_now"]}")
    {:noreply, socket}
  end

  def handle_info({:telemetry, "unlock_status", data}, socket) do
    {:noreply, assign(socket,
      unlock_votes_collected: data["unlock_votes_collected"] || 0,
      unlock_state:           data["unlock_state"]           || "IDLE",
      unlock_approvers:       data["unlock_approvers"]       || []
    )}
  end

  def handle_info({:telemetry, "scan_quarantine_result", data}, socket) do
    socket = assign(socket, last_scan_result: data)
    socket = push_terminal(socket, "AUDIT", "scan result=#{data["status"]} quarantined=#{data["quarantined"]}")
    {:noreply, socket}
  end

  def handle_info({:telemetry, "block_ip_result", data}, socket) do
    socket = assign(socket, last_block_result: data)
    socket = push_terminal(socket, "RULE", "firewall block ip=#{data["ip"]} ttl=#{data["ttl_s"]}s")
    {:noreply, socket}
  end

  def handle_info({:telemetry, "triage_result", data}, socket) do
    socket = assign(socket, last_triage: data)
    socket = push_terminal(socket, "AI",
      "triage result fast=#{data["fast_route"]} model=#{data["fast_model"]} " <>
      "final_tier=#{tier_int_to_name(data["final_tier"])} override=#{data["rule_engine_overrode"]}")
    {:noreply, socket}
  end

  def handle_info({:telemetry, "veeam_check_result", data}, socket) do
    {:noreply, assign(socket,
      veeam_integrity_checks: (socket.assigns.veeam_integrity_checks || 0) + 1,
      veeam_lock_state: data["lock_state"] || socket.assigns.veeam_lock_state
    )}
  end

  def handle_info({:telemetry, "veeam_status", data}, socket) do
    {:noreply, assign(socket,
      veeam_lock_state:       data["lock_state"]            || "UNLOCKED",
      veeam_backup_count:     data["backup_count"]          || 0,
      veeam_locked_at_ms:     data["locked_at_ms"]          || 0,
      veeam_integrity_checks: data["integrity_check_count"] || 0,
      veeam_locked_by_reason: data["locked_by_reason"]      || ""
    )}
  end

  def handle_info({:telemetry, "demo_done", _data}, socket) do
    {:noreply, assign(socket, demo_running: false)}
  end

  def handle_info({:telemetry, "demo_started_async", _data}, socket) do
    {:noreply, assign(socket, demo_running: true)}
  end

  def handle_info({:telemetry, "agent_status_update", data}, socket) do
    statuses = data["agent_statuses"] || []
    # Fallback to demo agents if bridge returns empty
    statuses = if statuses == [], do: demo_agents(), else: statuses
    {:noreply, assign(socket,
      agent_statuses:    statuses,
      agent_queue_depth: data["agent_queue_depth"] || 0
    )}
  end

  def handle_info({:telemetry, "agent_task_result", data}, socket) do
    socket = assign(socket, last_agent_task_id: data["task_id"], last_agent_result: data)
    socket = push_terminal(socket, "AGENT",
      "task_result agent=#{data["agent_name"]} ok=#{data["ok"]} route=#{agent_model_label(data["model_used"])}")
    {:noreply, socket}
  end

  def handle_info({:telemetry, "terminal_execute_result", data}, socket) do
    output = terminal_execution_output(data)
    summary = terminal_execution_summary(data)

    socket =
      socket
      |> assign(terminal_cmd_output: output)
      |> push_terminal("TERM", summary)

    {:noreply, socket}
  end

  def handle_info({:telemetry, "runtime_status", data}, socket) do
    socket =
      socket
      |> assign(runtime_status: data, runtime_status_state: "ready")
      |> push_terminal("AUDIT", runtime_status_summary(data))

    {:noreply, socket}
  end

  def handle_info({:telemetry, "decoy_triggered", data}, socket) do
    socket = push_terminal(socket, "DECOY",
      "TRIGGERED path=#{data["path"] || "?"} attacker=#{data["tag"] || "unknown"}")
    {:noreply, socket}
  end

  def handle_info({:telemetry, "rule_fired", data}, socket) do
    socket = push_terminal(socket, "RULE",
      "#{data["rule_id"] || "RULE"} fired — #{data["reason"] || ""}")
    {:noreply, socket}
  end

  # The bridge exposes configured policy zones, rather than claiming to scan a
  # physical wireless estate.  Keep the UI vocabulary and event contract exact.
  def handle_info({:telemetry, "network_ssids", data}, socket) do
    {:noreply, assign(socket, nac_ssids: data["ssids"] || [])}
  end

  def handle_info({:telemetry, "nac_result", data}, socket) do
    result = data["result"] || "DENY"

    socket = assign(socket, nac_result: data, nac_step: 8)
    socket = push_terminal(socket, "NAC",
      "policy simulation device=#{data["device_mac"] || "?"} result=#{result} vlan=#{data["assigned_vlan"] || "none"}")

    {:noreply, socket}
  end

  def handle_info({:telemetry, "zerotrust_result", data}, socket) do
    decision = data["decision"] || "DENY"

    socket = assign(socket, zt_result: data)
    socket = push_terminal(socket, "ZT",
      "policy evaluation user=#{data["user_id"] || "?"} resource=#{data["requested_resource"] || "?"} decision=#{decision} trust=#{data["trust_score"] || "?"}")

    {:noreply, socket}
  end

  def handle_info({:telemetry, "snapshot", data}, socket) do
    {:noreply, socket |> assign_state(data)}
  end

  def handle_info({:telemetry, "ready", _data}, socket) do
    # Fetch SSIDs and agent statuses on connect
    AstartisWeb.Core.AstartisPort.send_command(%{"cmd" => "network_get_ssids", "args" => %{}})
    AstartisWeb.Core.AstartisPort.send_command(%{"cmd" => "agent_status", "args" => %{}})
    AstartisWeb.Core.AstartisPort.send_command(%{"cmd" => "packet_capture_list_adapters", "args" => %{}})
    request_runtime_status()
    {:noreply, socket}
  end

  def handle_info({:telemetry, _event, _data}, socket), do: {:noreply, socket}


  # ---------------------------------------------------------------------------
  # User events
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("switch_app", %{"app" => app}, socket) do
    {:noreply, assign(socket, active_app: app)}
  end

  def handle_event("packet_capture_start", _params, socket) do
    AstartisWeb.Core.AstartisPort.send_command(%{"cmd" => "packet_capture_start", "args" => %{"adapter_hint" => socket.assigns.capture_adapter_choice || ""}})
    socket =
      socket
      |> clear_capture_start_timer()
      |> assign(
        capture_action_state: "starting",
        capture_error: nil,
        capture_start_timer: Process.send_after(self(), :capture_start_timeout, 8_000)
      )
    {:noreply, push_terminal(socket, "PACKET", "Starting live Npcap capture on the active adapter")}
  end

  def handle_event("packet_capture_stop", _params, socket) do
    AstartisWeb.Core.AstartisPort.send_command(%{"cmd" => "packet_capture_stop", "args" => %{}})
    socket = socket |> clear_capture_start_timer() |> assign(capture_action_state: "stopping")
    {:noreply, push_terminal(socket, "PACKET", "Stopping Npcap capture")}
  end

  def handle_event("packet_capture_adapter_select", %{"adapter" => adapter}, socket) do
    {:noreply, assign(socket, capture_adapter_choice: adapter)}
  end

  def handle_event("set_dashboard_density", %{"density" => density}, socket) when density in ["comfortable", "compact"] do
    {:noreply, assign(socket, dashboard_density: density)}
  end

  def handle_event("set_dashboard_density", _params, socket), do: {:noreply, socket}

  def handle_event("set_evidence_window", %{"window" => window}, socket) when window in ["Current session", "Last 24 hours", "Last 7 days"] do
    {:noreply, assign(socket, evidence_window_label: window)}
  end

  def handle_event("set_evidence_window", _params, socket), do: {:noreply, socket}

  def handle_event("set_terminal_dock_visibility", %{"visibility" => visibility}, socket) when visibility in ["visible", "hidden"] do
    {:noreply, assign(socket, terminal_dock_visible: visibility == "visible")}
  end

  def handle_event("set_terminal_dock_visibility", _params, socket), do: {:noreply, socket}

  def handle_event("refresh_runtime_status", _params, socket) do
    request_runtime_status()

    {:noreply,
     socket
     |> assign(runtime_status_state: "requesting")
     |> push_terminal("AUDIT", "Requested one-time live local runtime sample")}
  end

  def handle_event("run_demo", _params, socket) do
    Task.start(fn -> DemoScript.run() end)
    Task.start(fn ->
      Process.sleep(8_000)
      DemoScript.get_attribution("demo-atk")
    end)
    socket = push_terminal(socket, "AGENT", "Demo sequence started — LOW→CRIT escalation")
    {:noreply, assign(socket, demo_running: true)}
  end

  def handle_event("switch_tab", %{"tab" => tab}, socket) do
    {:noreply, assign(socket, active_tab: tab)}
  end

  def handle_event("worm_unlock", _params, socket) do
    DemoScript.unlock_worm("dashboard_user")
    {:noreply, socket}
  end

  def handle_event("cast_unlock_vote", %{"approver" => approver}, socket) do
    AstartisWeb.Core.AstartisPort.send_command(%{
      "cmd"  => "unlock_vote",
      "args" => %{"approver" => approver}
    })
    {:noreply, socket}
  end

  def handle_event("veeam_integrity_check", _params, socket) do
    AstartisWeb.Core.AstartisPort.send_command(%{"cmd" => "veeam_integrity_check", "args" => %{}})
    {:noreply, socket}
  end

  def handle_event("run_triage", %{"event_type" => et, "score" => score_str}, socket) do
    score = String.to_integer(score_str)
    AstartisWeb.Core.AstartisPort.send_command(%{
      "cmd"  => "triage_event",
      "args" => %{"event_type" => et, "source" => "dashboard_user", "score" => score,
                  "detail" => "Manual triage (score=#{score})"}
    })
    socket = push_terminal(socket, "AI", "triage triggered event=#{et} score=#{score}")
    {:noreply, assign(socket, last_triage: :pending)}
  end

  def handle_event("select_pipeline_stage", %{"stage" => stage}, socket) do
    new_stage = if socket.assigns.pipeline_stage == stage, do: nil, else: stage
    {:noreply, assign(socket, pipeline_stage: new_stage)}
  end

  def handle_event("agent_submit_task", %{"agent" => agent, "input" => input}, socket) do
    AstartisWeb.Core.AstartisPort.send_command(%{
      "cmd"  => "agent_submit",
      "args" => %{"agent_name" => agent, "input" => input, "priority" => "normal"}
    })
    socket = push_terminal(socket, "AGENT", "submitted task agent=#{agent} input=#{String.slice(input, 0, 60)}")
    {:noreply, assign(socket, last_agent_task_id: :pending)}
  end

  def handle_event("nac_simulate", params, socket) do
    mac  = params["mac"]  || socket.assigns.nac_device_mac
    type = params["type"] || socket.assigns.nac_device_type
    ssid = params["ssid"] || socket.assigns.nac_selected_ssid || "eGov"
    compliant = type == "CORP"
    username = if compliant, do: "kgosi.blanda", else: "demo.contractor"

    AstartisWeb.Core.AstartisPort.send_command(%{
      "cmd"  => "nac_simulate_device",
      "args" => %{
        "device_mac" => mac,
        "device_name" => "dashboard-#{String.downcase(type)}",
        "ssid_name" => ssid,
        "username" => username,
        "domain" => "egov.gov.bw",
        "os_updated" => compliant,
        "antivirus_running" => compliant,
        "disk_encrypted" => compliant,
        "firewall_enabled" => compliant
      }
    })

    socket = push_terminal(socket, "NAC", "running deterministic policy simulation mac=#{mac} profile=#{type} ssid=#{ssid}")
    {:noreply, assign(socket, nac_device_mac: mac, nac_device_type: type, nac_step: 1, nac_result: nil)}
  end

  def handle_event("nac_select_ssid", %{"ssid" => ssid}, socket) do
    {:noreply, assign(socket, nac_selected_ssid: ssid)}
  end

  def handle_event("nac_set_device", params, socket) do
    {:noreply, assign(socket,
      nac_device_mac:  params["mac"]  || socket.assigns.nac_device_mac,
      nac_device_type: params["type"] || socket.assigns.nac_device_type
    )}
  end

  def handle_event("zt_evaluate", params, socket) do
    request = %{
      "user_id" => params["user_id"] || "demo.contractor",
      "device_id" => params["device_id"] || "02:42:ac:11:00:09",
      "source_ip" => params["source_ip"] || "10.200.0.25",
      "destination_ip" => params["destination_ip"] || "10.200.0.10",
      "requested_resource" => params["requested_resource"] || "citizen-records",
      "ssid_name" => params["ssid_name"] || "eGov"
    }

    AstartisWeb.Core.AstartisPort.send_command(%{
      "cmd"  => "zerotrust_evaluate",
      "args" => request
    })

    socket = push_terminal(socket, "ZT", "evaluating deterministic policy user=#{request["user_id"]} resource=#{request["requested_resource"]}")
    {:noreply, assign(socket, zt_result: :pending)}
  end

  def handle_event("sandbox_select", %{"path" => path}, socket) do
    entry = Enum.find(socket.assigns.sandbox_entries, &(&1["rel_path"] == path))
    {:noreply, assign(socket, sandbox_selected: entry)}
  end

  def handle_event("sandbox_lock", %{"path" => path}, socket) do
    AstartisWeb.Core.AstartisPort.send_command(%{
      "cmd"  => "sandbox_lock_entry",
      "args" => %{"path" => path}
    })
    socket = push_terminal(socket, "SANDBOX", "locked path=#{path}")
    {:noreply, socket}
  end

  def handle_event("plant_decoy", _params, socket) do
    AstartisWeb.Core.AstartisPort.send_command(%{
      "cmd"  => "decoy_plant",
      "args" => %{"type" => "credential", "path" => "home/admin/.aws/credentials"}
    })
    socket = push_terminal(socket, "DECOY", "planted credential decoy at home/admin/.aws/credentials")
    {:noreply, socket}
  end

  def handle_event("toggle_terminal_filter", %{"tag" => tag}, socket) do
    filters = socket.assigns.terminal_filters
    new_filters = if tag in filters, do: List.delete(filters, tag), else: [tag | filters]
    socket = push_event(socket, "terminal_filter", %{tag: tag, active: tag in new_filters})
    {:noreply, assign(socket, terminal_filters: new_filters)}
  end

  def handle_event("terminal_cmd", %{"cmd" => cmd}, socket) do
    command = String.trim(cmd)
    socket = push_terminal(socket, "TERM", "> #{command}")

    if terminal_builtin_command?(command) do
      output = handle_terminal_command(command, socket)
      {:noreply, assign(socket, terminal_cmd_output: output)}
    else
      AstartisWeb.Core.AstartisPort.send_command(%{
        "cmd" => "terminal_execute",
        "args" => %{"command" => command}
      })

      {:noreply,
       assign(socket,
         terminal_cmd_output:
           "Requesting local diagnostic through Astartis' read-only allowlist…"
       )}
    end
  end

  def handle_event("toggle_about_modal", _params, socket) do
    {:noreply, assign(socket, show_about_modal: !socket.assigns.show_about_modal)}
  end

  def handle_event("toggle_worm_modal", _params, socket) do
    {:noreply, assign(socket, show_worm_modal: !socket.assigns.show_worm_modal)}
  end

  def handle_event("close_modal", _params, socket) do
    {:noreply, assign(socket, show_about_modal: false, show_worm_modal: false)}
  end

  # ---------------------------------------------------------------------------
  # Terminal command handler
  # ---------------------------------------------------------------------------

  defp handle_terminal_command("help", _socket) do
    "Astartis commands: status | agents | worm | worm status | network | pipeline | audit | agent submit <name> <input>\n" <>
      "Live local diagnostics: ipconfig /all | whoami | hostname | systeminfo | netstat -ano | Get-NetAdapter\n" <>
      "All other operating-system commands are rejected by the bridge policy."
  end
  defp handle_terminal_command("status", socket) do
    a = socket.assigns
    "Threat: #{a.threat_tier_name} | WORM: #{if a.worm_locked, do: "LOCKED", else: "NORMAL"} | K: #{Float.round(a.chaos_K + 0.0, 3)} | Chain: #{a.chain_length}"
  end
  defp handle_terminal_command("agents", socket) do
    n = length(socket.assigns.agent_statuses)
    r = Enum.count(socket.assigns.agent_statuses, &(&1["state"] == "RUNNING"))
    "#{n} agents loaded | #{r} running | queue=#{socket.assigns.agent_queue_depth}"
  end
  defp handle_terminal_command("worm", _socket) do
    "Usage: worm status | worm lock | worm unlock"
  end
  defp handle_terminal_command("worm status", socket) do
    a = socket.assigns
    "WORM: #{if a.worm_locked, do: "LOCKED", else: "NORMAL"} | activations=#{a.worm_lock_count} | reason=#{if a.worm_reason == "", do: "none", else: a.worm_reason}"
  end
  defp handle_terminal_command("worm lock", _socket) do
    AstartisWeb.Core.AstartisPort.send_command(%{"cmd" => "worm_trigger", "args" => %{"reason" => "manual_terminal"}})
    "WORM lockdown requested"
  end
  defp handle_terminal_command("worm unlock", _socket) do
    DemoScript.unlock_worm("terminal_user")
    "WORM unlock requested"
  end
  defp handle_terminal_command("network", socket) do
    "Chaos windows=#{socket.assigns.chaos_windows} K=#{Float.round(socket.assigns.chaos_K + 0.0, 4)} anomalous=#{socket.assigns.chaos_anomalous}"
  end
  defp handle_terminal_command("pipeline", socket) do
    a = socket.assigns
    "Pipeline: tier=#{a.threat_tier_name} rule_fires=#{a.rule_fires} decoy_events=#{a.decoy_events} chain=#{a.chain_length}"
  end
  defp handle_terminal_command("audit", socket) do
    "Chain: length=#{socket.assigns.chain_length} valid=#{socket.assigns.chain_valid} head=#{socket.assigns.chain_head}"
  end
  defp handle_terminal_command("agent submit " <> rest, _socket) do
    cmd = "agent submit " <> rest
    parts = String.split(cmd, " ", parts: 4)
    case parts do
      [_, _, agent, input] ->
        AstartisWeb.Core.AstartisPort.send_command(%{
          "cmd"  => "agent_submit",
          "args" => %{"agent_name" => agent, "input" => input, "priority" => "normal"}
        })
        "Task submitted to #{agent}"
      _ -> "Usage: agent submit <agent_name> <input>"
    end
  end
  defp handle_terminal_command(cmd, _socket), do: "Unknown command: #{cmd}. Type 'help' for commands."

  defp terminal_builtin_command?(command) do
    command in [
      "help",
      "status",
      "agents",
      "worm",
      "worm status",
      "worm lock",
      "worm unlock",
      "network",
      "pipeline",
      "audit"
    ] or String.starts_with?(command, "agent submit ")
  end

  defp terminal_execution_summary(data) do
    command = data["command"] || "diagnostic"

    cond do
      data["rejected"] ->
        "REJECTED command=#{command} policy=read-only diagnostic allowlist"

      data["timed_out"] ->
        "TIMED OUT command=#{command} duration=#{data["duration_ms"] || "?"}ms"

      data["executed"] ->
        "COMPLETED command=#{command} exit=#{data["exit_code"] || 0} duration=#{data["duration_ms"] || "?"}ms mode=live_local"

      true ->
        "FAILED command=#{command} status=#{data["status"] || "error"}"
    end
  end

  defp terminal_execution_output(data) do
    command = data["command"] || "diagnostic"
    status = data["status"] || "error"
    mode = data["mode"] || "live_local"
    duration = data["duration_ms"] || 0
    exit_code = data["exit_code"] || -1

    header =
      "$ #{command}\n" <>
        "status: #{status} · mode: #{mode} · exit: #{exit_code} · duration: #{duration}ms\n"

    stdout = String.trim(data["stdout"] || "")
    stderr = String.trim(data["stderr"] || "")

    [
      header,
      if(stdout == "", do: nil, else: "\nSTDOUT\n#{stdout}"),
      if(stderr == "", do: nil, else: "\nSTDERR\n#{stderr}"),
      if(data["stdout_truncated"], do: "\n[stdout truncated at bridge safety limit]", else: nil),
      if(data["stderr_truncated"], do: "\n[stderr truncated at bridge safety limit]", else: nil),
      if(data["rejected"], do: "\nNo process was started.", else: nil)
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join("")
  end


  # ---------------------------------------------------------------------------
  # Render — complete OS-grade dashboard
  # ---------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    ~H"""
    <%
      {capture_label, capture_tone} = telemetry_status(assigns)
      {evidence_label, evidence_tone} = evidence_status(assigns)
    %>
    <div class={"os-root density-#{@dashboard_density}"}>
      <style>
        /* ===== RESET ===== */
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        /* ===== CSS VARIABLES ===== */
        :root {
          --bg-primary:   #f4f4f4;
          --bg-secondary: #ffffff;
          --bg-panel:     #ffffff;
          --bg-input:     #ffffff;
          --border:       #dde1e6;
          --text-primary: #161616;
          --text-secondary:#525252;
          --ibm-blue:     #0f62fe;
          --ibm-granite:  #0f62fe;
          --success:      #198038;
          --warning:      #f1c21b;
          --danger:       #da1e28;
          --info:         #0f62fe;
          --accent-moe:   #007d79;
          --accent-dense: #8a3ffc;
          --glow:         none;
          --glow-danger:  none;
          --glass-bg:     #ffffff;
          --glass-border: #dde1e6;
          --glass-glow:   0 1px 2px rgba(22, 22, 22, 0.12);
        }

        /* ===== BASE ===== */
        html, body {
          background: var(--bg-primary);
          background-image: none;
          color: var(--text-primary);
          font-family: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
          font-size: 14px;
          line-height: 1.6;
          height: 100vh;
          overflow: hidden;
        }
        .mono { font-family: "IBM Plex Mono", "Consolas", monospace; }

        /* ===== OS LAYOUT ===== */
        .os-root {
          display: flex;
          flex-direction: column;
          height: 100vh;
          overflow: hidden;
        }

        /* ===== TOP BAR ===== */
        .topbar {
          background: #ffffff;
          border-bottom: 1px solid #dde1e6;
          padding: 0 24px;
          height: 56px;
          display: flex;
          align-items: center;
          gap: 12px;
          flex-shrink: 0;
          z-index: 100;
          box-shadow: none;
        }
        .topbar-logo {
          display: flex;
          align-items: center;
          gap: 8px;
          cursor: pointer;
          text-decoration: none;
        }
        .topbar-diamond {
          width: 24px;
          height: 24px;
          flex-shrink: 0;
        }
        .topbar-brand {
          font-size: 13px;
          font-weight: 700;
          color: #161616;
          letter-spacing: 0.08em;
          white-space: nowrap;
        }
        .topbar-brand-suite { display: flex; align-items: baseline; gap: 7px; }
        .topbar-brand-divider { color: #8d8d8d; font-size: 13px; font-weight: 400; }
        .topbar-brand-codex { color: #0f62fe; font-size: 11px; font-weight: 700; letter-spacing: .08em; }
        .topbar-center {
          flex: 1;
          text-align: center;
          font-size: 11px;
          font-weight: 700;
          color: #525252;
          letter-spacing: 0.12em;
          text-transform: uppercase;
        }
        .topbar-pills {
          display: flex;
          gap: 8px;
          align-items: center;
        }
        .pill {
          display: flex;
          align-items: center;
          gap: 5px;
          padding: 3px 10px;
          border-radius: 12px;
          font-size: 11px;
          font-weight: 700;
          cursor: pointer;
          border: 1px solid transparent;
          transition: all 0.2s;
          white-space: nowrap;
        }
        .pill:hover { filter: brightness(1.2); }
        .pill-LOW      { background: #defbe6; color: #0e6027; border-color: #a7f0ba; }
        .pill-MEDIUM   { background: #fff1c2; color: #684e00; border-color: #f1c21b; }
        .pill-HIGH     { background: #fff1f1; color: #a2191f; border-color: #ffb3b8; }
        .pill-CRITICAL { background: #f6f2ff; color: #6929c4; border-color: #d4bbff; animation: pulse 1s infinite; }
        .pill-worm-normal { background: #defbe6; color: #0e6027; border-color: #a7f0ba; }
        .pill-worm-locked { background: #fff1f1; color: #a2191f; border-color: #ffb3b8; animation: pulse 0.8s infinite; }
        .pill-clock { background: #f4f4f4; color: #525252; border-color: #dde1e6; font-family: monospace; font-size: 11px; }
        .topbar-evidence { background: #edf5ff; color: #0043ce; border-color: #a6c8ff; cursor: default; }
        .topbar-evidence--live, .topbar-evidence--verified { background: #defbe6; color: #0e6027; border-color: #a7f0ba; }
        .topbar-evidence--simulation { background: #fff1c2; color: #684e00; border-color: #f1c21b; }
        .topbar-evidence--review { background: #fff1f1; color: #a2191f; border-color: #ffb3b8; }
        .topbar-evidence--neutral { background: #f4f4f4; color: #525252; border-color: #dde1e6; }

        /* ===== MAIN DESKTOP ===== */
        .desktop {
          display: flex;
          flex: 1;
          overflow: hidden;
        }

        /* ===== APP DOCK ===== */
        .app-dock {
          width: 208px;
          background: #ffffff;
          border-right: 1px solid #dde1e6;
          display: flex;
          flex-direction: column;
          align-items: stretch;
          padding: 16px 12px;
          gap: 2px;
          flex-shrink: 0;
          overflow-y: auto;
          scrollbar-width: thin;
          scrollbar-color: var(--border) transparent;
          box-shadow: none;
        }
        .dock-item {
          width: 100%;
          height: 40px;
          border-radius: 0;
          display: flex;
          flex-direction: row;
          align-items: center;
          justify-content: flex-start;
          cursor: pointer;
          position: relative;
          transition: all 0.2s;
          border: 1px solid transparent;
          font-size: 13px;
          gap: 10px;
          padding: 0 12px;
          background: transparent;
          color: var(--text-secondary);
        }
        .dock-item:hover {
          background: #edf5ff;
          border-color: transparent;
          color: #0f62fe;
          transform: none;
        }
        .dock-item.active {
          background: #edf5ff;
          border-color: transparent;
          box-shadow: inset 3px 0 0 #0f62fe;
          color: #0f62fe;
          animation: none;
        }
        @keyframes dock-glow {
          0%, 100% { box-shadow: 0 0 5px rgba(69, 137, 255, 0.3), 0 0 12px rgba(69, 137, 255, 0.35); }
          50% { box-shadow: 0 0 15px rgba(69, 137, 255, 0.6), 0 0 30px rgba(69, 137, 255, 0.2); }
        }
        .dock-label {
          font-size: 13px;
          text-transform: none;
          letter-spacing: 0;
          line-height: 1;
          color: inherit;
        }
        .dock-icon {
          width: 32px;
          color: #525252;
          font-size: 10px;
          font-weight: 700;
          letter-spacing: .04em;
          line-height: 1;
          text-align: center;
        }
        .dock-item.active .dock-icon { color: #0f62fe; }
        .dock-badge {
          position: absolute;
          top: 4px;
          right: 4px;
          width: 14px;
          height: 14px;
          border-radius: 50%;
          background: var(--danger);
          color: white;
          font-size: 8px;
          font-weight: 700;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        /* ===== MAIN AREA ===== */
        .main-area {
          flex: 1;
          overflow-y: auto;
          overflow-x: hidden;
          padding: 32px;
          scrollbar-width: thin;
          scrollbar-color: var(--border) transparent;
        }

        /* ===== TERMINAL WORKSPACE ===== */
        .terminal-dock { min-height: 48px; padding: 0 20px; border-top: 1px solid #dde1e6; background: #fff; display: flex; align-items: center; gap: 16px; flex-shrink: 0; }
        .terminal-dock-open { display: inline-flex; align-items: center; gap: 9px; min-height: 47px; padding: 0 2px; border: 0; border-bottom: 2px solid transparent; background: transparent; color: #161616; cursor: pointer; font-size: 13px; font-weight: 600; }
        .terminal-dock-open:hover, .terminal-dock-open:focus-visible { color: #0f62fe; border-bottom-color: #0f62fe; outline: 0; }
        .terminal-dock-count { padding: 1px 6px; background: #e0e0e0; color: #525252; font-family: "IBM Plex Mono", "Consolas", monospace; font-size: 10px; font-weight: 600; }
        .terminal-dock-status { display: flex; align-items: center; gap: 10px; min-width: 0; color: #525252; font-size: 12px; }
        .terminal-dock-status span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .terminal-dock-link { margin-left: auto; border: 0; background: transparent; color: #0f62fe; cursor: pointer; font-size: 12px; font-weight: 600; }
        .terminal-dock-link:hover { color: #0043ce; text-decoration: underline; }
        .terminal-workspace { max-width: 1440px; margin: 0 auto; }
        .terminal-workspace-hero { display: flex; align-items: flex-end; justify-content: space-between; gap: 24px; padding: 4px 0 28px; border-bottom: 1px solid #dde1e6; }
        .terminal-workspace-kicker { margin: 0 0 8px; color: #525252; font-size: 12px; font-weight: 600; letter-spacing: .02em; text-transform: uppercase; }
        .terminal-workspace-title { margin: 0; color: #161616; font-size: 32px; font-weight: 500; letter-spacing: -.02em; line-height: 1.15; }
        .terminal-workspace-subtitle { max-width: 720px; margin: 12px 0 0; color: #525252; font-size: 15px; line-height: 1.5; }
        .terminal-status-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1px; margin: 28px 0 24px; border: 1px solid #dde1e6; background: #dde1e6; }
        .terminal-status-card { min-height: 118px; padding: 18px 20px; background: #fff; display: flex; flex-direction: column; justify-content: space-between; }
        .terminal-status-card-label { color: #525252; font-size: 13px; }
        .terminal-status-card-value { color: #161616; font-size: 21px; font-weight: 500; line-height: 1.2; }
        .terminal-status-card-note { color: #525252; font-size: 12px; }
        .terminal-state-chip { display: inline-flex; align-items: center; width: fit-content; padding: 3px 7px; font-size: 11px; font-weight: 600; }
        .terminal-state-chip--live, .terminal-state-chip--verified { background: #defbe6; color: #0e6027; }
        .terminal-state-chip--simulation { background: #fff1c2; color: #684e00; }
        .terminal-state-chip--review { background: #fff1f1; color: #a2191f; }
        .terminal-state-chip--neutral { background: #e0e0e0; color: #525252; }
        .terminal-console { border: 1px solid #dde1e6; background: #fff; }
        .terminal-console-toolbar { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; padding: 20px; border-bottom: 1px solid #dde1e6; }
        .terminal-console-title { margin: 0; color: #161616; font-size: 18px; font-weight: 500; letter-spacing: -.01em; }
        .terminal-console-description { margin: 5px 0 0; color: #525252; font-size: 13px; line-height: 1.45; }
        .terminal-console-filters { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 6px; }
        .terminal-filter-btn { padding: 4px 7px; border: 1px solid currentColor; background: #fff; cursor: pointer; font-family: "IBM Plex Mono", "Consolas", monospace; font-size: 10px; font-weight: 600; letter-spacing: .02em; }
        .terminal-filter-btn:hover { background: #edf5ff; }
        .terminal-filter-btn.off { opacity: .35; }
        .terminal-log { min-height: 350px; max-height: 520px; overflow: auto; padding: 4px 0; background: #f4f4f4; font-family: "IBM Plex Mono", "Consolas", monospace; font-size: 12px; line-height: 1.55; }
        .terminal-line { display: grid; grid-template-columns: 95px 88px minmax(0, 1fr); gap: 8px; padding: 5px 20px; color: #262626; }
        .terminal-line:hover { background: #edf5ff; }
        .terminal-line-time { color: #6f6f6f; }
        .terminal-line-tag { color: var(--terminal-tag); font-weight: 700; }
        .terminal-line-text { min-width: 0; overflow-wrap: anywhere; }
        .terminal-empty { padding: 48px 24px; color: #525252; text-align: center; }
        .terminal-command-output { margin: 0 20px 20px; padding: 12px; border-left: 3px solid #0f62fe; background: #edf5ff; color: #161616; font-family: "IBM Plex Mono", "Consolas", monospace; font-size: 12px; line-height: 1.5; }
        .terminal-command-row { display: flex; align-items: center; gap: 10px; padding: 16px 20px; border-top: 1px solid #dde1e6; background: #fff; }
        .terminal-prompt { color: #0f62fe; font-family: "IBM Plex Mono", "Consolas", monospace; font-size: 12px; font-weight: 700; white-space: nowrap; }
        .terminal-input { flex: 1; min-width: 0; min-height: 40px; padding: 0 12px; border: 1px solid #8d8d8d; background: #fff; color: #161616; font-family: "IBM Plex Mono", "Consolas", monospace; font-size: 13px; outline: 0; }
        .terminal-input:focus { outline: 2px solid #0f62fe; outline-offset: 2px; border-color: #0f62fe; }

        /* ===== RUNTIME & WORKSPACE CONFIGURATION ===== */
        .runtime-settings { max-width: 1440px; margin: 0 auto; }
        .runtime-settings-grid { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(320px, .8fr); gap: 24px; align-items: start; margin-top: 24px; }
        .runtime-settings-panel { border: 1px solid #dde1e6; background: #fff; }
        .runtime-settings-panel + .runtime-settings-panel { margin-top: 24px; }
        .runtime-settings-panel-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding: 20px; border-bottom: 1px solid #dde1e6; }
        .runtime-settings-panel-title { margin: 0; color: #161616; font-size: 18px; font-weight: 500; letter-spacing: -.01em; }
        .runtime-settings-panel-description { margin: 5px 0 0; color: #525252; font-size: 13px; line-height: 1.45; }
        .runtime-settings-readonly { display: inline-flex; align-items: center; padding: 3px 7px; background: #e0e0e0; color: #525252; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .03em; white-space: nowrap; }
        .runtime-list { padding: 2px 20px 14px; }
        .runtime-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 20px; padding: 14px 0; border-bottom: 1px solid #e0e0e0; }
        .runtime-row:last-child { border-bottom: 0; }
        .runtime-row-label { color: #161616; font-size: 13px; font-weight: 600; }
        .runtime-row-note { margin-top: 3px; color: #525252; font-size: 12px; line-height: 1.4; }
        .runtime-row-value { max-width: 340px; color: #161616; font-family: "IBM Plex Mono", "Consolas", monospace; font-size: 12px; text-align: right; overflow-wrap: anywhere; }
        .runtime-config-form { padding: 20px; display: flex; flex-direction: column; gap: 16px; }
        .runtime-config-field { display: flex; flex-direction: column; gap: 7px; }
        .runtime-config-label { color: #161616; font-size: 13px; font-weight: 600; }
        .runtime-config-help { color: #525252; font-size: 12px; line-height: 1.4; }
        .runtime-config-select { min-height: 40px; padding: 0 12px; border: 1px solid #8d8d8d; border-radius: 0; background: #fff; color: #161616; font-size: 13px; }
        .runtime-config-select:focus { outline: 2px solid #0f62fe; outline-offset: 2px; border-color: #0f62fe; }
        .runtime-config-select:disabled { background: #f4f4f4; color: #6f6f6f; cursor: not-allowed; }
        .runtime-settings-note { margin: 0 20px 20px; padding: 12px; border-left: 3px solid #0f62fe; background: #edf5ff; color: #161616; font-size: 12px; line-height: 1.5; }
        .density-compact .main-area { padding: 20px; }
        .density-compact .card { padding: 16px 20px; margin-bottom: 12px; }
        .density-compact .terminal-dock { min-height: 42px; }
        .density-compact .terminal-dock-open { min-height: 41px; }

        /* ===== CARDS ===== */
        .card {
          background: #ffffff;
          border: 1px solid var(--glass-border);
          border-radius: 0;
          padding: 20px 24px;
          margin-bottom: 16px;
          box-shadow: var(--glass-glow);
          transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
          position: relative;
          overflow: hidden;
        }
        .card::before {
          display: none;
        }
        .card:hover {
          border-color: #a6c8ff;
          box-shadow: 0 1px 2px rgba(22, 22, 22, 0.12);
          transform: none;
        }
        .card.glow { 
          box-shadow: 0 4px 24px rgba(0, 0, 0, 0.4), 0 0 25px rgba(69, 137, 255, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.05); 
        }
        .card.glow:hover {
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5), 0 0 50px rgba(69, 137, 255, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        }
        .card-title {
          font-size: 10px;
          text-transform: uppercase;
          letter-spacing: 0.12em;
          color: var(--text-secondary);
          margin-bottom: 10px;
          display: flex;
          align-items: center;
          gap: 8px;
          font-weight: 600;
        }
        .section-header {
          font-size: 13px;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.1em;
          color: var(--ibm-granite);
          margin-bottom: 16px;
          padding-bottom: 10px;
          border-bottom: 1px solid rgba(69, 137, 255, 0.2);
          display: flex;
          align-items: center;
          justify-content: space-between;
          text-shadow: 0 0 20px rgba(69, 137, 255, 0.3);
        }
          border-bottom: 1px solid var(--border);
          display: flex;
          align-items: center;
          justify-content: space-between;
        }
        .granite-badge {
          font-size: 9px;
          color: var(--ibm-granite);
          border: 1px solid var(--ibm-granite);
          padding: 1px 6px;
          border-radius: 4px;
          font-weight: 700;
          letter-spacing: 0.06em;
        }

        /* ===== TIER BADGES ===== */
        .tier-badge { display: inline-block; padding: 5px 14px; border-radius: 16px; font-weight: 700; font-size: 13px; letter-spacing: 0.06em; }
        .tier-LOW      { background: #064e3b; color: #6ee7b7; border: 1px solid #059669; box-shadow: 0 0 10px rgba(16, 185, 129, 0.3); }
        .tier-MEDIUM   { background: #78350f; color: #fcd34d; border: 1px solid #d97706; box-shadow: 0 0 10px rgba(245, 158, 11, 0.3); }
        .tier-HIGH     { background: #7c2d12; color: #fca5a5; border: 1px solid #dc2626; box-shadow: 0 0 10px rgba(239, 68, 68, 0.3); }
        .tier-CRITICAL { background: #581c87; color: #e9d5ff; border: 1px solid #9333ea; animation: pulse 1s infinite; box-shadow: 0 0 15px rgba(147, 51, 234, 0.4); }
        .worm-locked   { background: #7c2d12; color: #fca5a5; border: 1px solid #dc2626; padding: 5px 12px; border-radius: 6px; font-weight: 700; box-shadow: 0 0 10px rgba(239, 68, 68, 0.3); }
        .worm-normal   { background: #064e3b; color: #6ee7b7; border: 1px solid #059669; padding: 5px 12px; border-radius: 6px; box-shadow: 0 0 10px rgba(16, 185, 129, 0.3); }

        /* ===== ANIMATIONS ===== */
        @keyframes pulse {
          0%,100% { opacity: 1; box-shadow: 0 0 15px currentColor; }
          50%      { opacity: 0.55; box-shadow: 0 0 5px currentColor; }
        }
        @keyframes slideIn {
          from { transform: translateX(20px); opacity: 0; }
          to   { transform: translateX(0);    opacity: 1; }
        }
        @keyframes blink {
          0%,100% { opacity: 1; }
          50%      { opacity: 0; }
        }
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(6px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes float {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(-5px); }
        }
        @keyframes shimmer {
          0% { background-position: -200% 0; }
          100% { background-position: 200% 0; }
        }
        @keyframes scanline {
          0% { transform: translateY(-100%); }
          100% { transform: translateY(100%); }
        }
        .anim-slide { animation: slideIn 0.3s ease-out; }
        .anim-fade  { animation: fadeIn 0.25s ease-out; }
        .anim-float { animation: float 3s ease-in-out infinite; }
        .cursor-blink { animation: blink 1s step-start infinite; }

        /* ===== SCANLINE EFFECT ===== */
        .scanline-overlay {
          position: fixed;
          top: 0; left: 0; right: 0; bottom: 0;
          pointer-events: none;
          z-index: 9999;
          opacity: 0.03;
          background: linear-gradient(to bottom, transparent 50%, rgba(0,0,0,0.1) 50%);
          background-size: 100% 4px;
        }

        /* ===== TOPBAR CRITICAL GLOW ===== */
        .topbar.critical { animation: bar-danger 1.2s ease-in-out infinite; }
        @keyframes bar-danger {
          0%, 100% { border-bottom-color: rgba(239, 68, 68, 0.3); box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
          50% { border-bottom-color: rgba(239, 68, 68, 0.9); box-shadow: 0 4px 30px rgba(239, 68, 68, 0.25); }
        }

        /* ===== CHAOS CANVAS ===== */
        .chaos-canvas-container {
          background: rgba(15, 15, 25, 0.6);
          border-radius: 12px;
          border: 1px solid rgba(69, 137, 255, 0.15);
          overflow: hidden;
        }
        .chaos-canvas-container canvas {
          display: block;
          width: 100%;
          height: 200px;
        }

        /* ===== AGENT TOOLTIP ===== */
        .agent-node {
          position: relative;
          cursor: pointer;
        }
        .agent-tooltip {
          position: absolute;
          bottom: calc(100% + 10px);
          left: 50%;
          transform: translateX(-50%);
          width: 260px;
          padding: 14px;
          background: rgba(20, 20, 35, 0.96);
          backdrop-filter: blur(16px);
          -webkit-backdrop-filter: blur(16px);
          border: 1px solid rgba(69, 137, 255, 0.3);
          border-radius: 12px;
          opacity: 0;
          visibility: hidden;
          transition: all 0.2s ease;
          z-index: 100;
          pointer-events: none;
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.6);
        }
        .agent-node:hover .agent-tooltip {
          opacity: 1;
          visibility: visible;
          transform: translateX(-50%) translateY(-4px);
        }
        .agent-tooltip::after {
          content: '';
          position: absolute;
          top: 100%;
          left: 50%;
          transform: translateX(-50%);
          border: 8px solid transparent;
          border-top-color: rgba(20, 20, 35, 0.96);
        }

        /* ===== GRID LAYOUTS ===== */
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }
        .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
        .grid-full { grid-column: 1 / -1; }

        /* ===== TABLES ===== */
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        th { text-align: left; color: var(--text-secondary); font-weight: 600; font-size: 10px; text-transform: uppercase; letter-spacing: 0.07em; padding: 6px 8px; border-bottom: 1px solid var(--border); }
        td { padding: 5px 8px; border-bottom: 1px solid rgba(42,42,62,0.6); }
        tr:hover td { background: rgba(255,255,255,0.02); }
        .table-scroll { max-height: 280px; overflow-y: auto; scrollbar-width: thin; scrollbar-color: var(--border) transparent; }

        /* ===== BADGES ===== */
        .badge { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; }
        .badge-green  { background: #064e3b; color: #6ee7b7; }
        .badge-red    { background: #7c2d12; color: #fca5a5; }
        .badge-yellow { background: #78350f; color: #fcd34d; }
        .badge-blue   { background: #1e3a5f; color: #60a5fa; }
        .badge-purple { background: #3b1f5e; color: #a78bfa; }
        .badge-moe    { background: rgba(0,212,170,0.15); color: #00d4aa; border: 1px solid #00d4aa; }
        .badge-dense  { background: rgba(168,85,247,0.15); color: #a855f7; border: 1px solid #a855f7; }

        /* ===== BUTTONS ===== */
        .btn { display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px; border-radius: 8px; border: none; cursor: pointer; font-size: 12px; font-weight: 600; transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); position: relative; overflow: hidden; }
        .btn:hover { filter: brightness(1.15); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3); }
        .btn:active { transform: translateY(0); }
        .btn-primary { background: linear-gradient(135deg, var(--ibm-granite), #2563eb); color: white; box-shadow: 0 2px 8px rgba(69, 137, 255, 0.3); }
        .btn-primary:hover { box-shadow: 0 4px 16px rgba(69, 137, 255, 0.4); }
        .btn-danger  { background: linear-gradient(135deg, var(--danger), #b91c1c); color: white; box-shadow: 0 2px 8px rgba(239, 68, 68, 0.3); }
        .btn-danger:hover { box-shadow: 0 4px 16px rgba(239, 68, 68, 0.4); }
        .btn-ghost   { background: var(--glass-bg); backdrop-filter: blur(8px); color: var(--text-primary); border: 1px solid var(--glass-border); }
        .btn-ghost:hover { border-color: rgba(69, 137, 255, 0.4); box-shadow: 0 0 12px rgba(69, 137, 255, 0.15); }
        .btn-sm { padding: 5px 12px; font-size: 11px; }

        /* ===== FORMS ===== */
        .input {
          background: var(--glass-bg);
          backdrop-filter: blur(8px);
          border: 1px solid var(--glass-border);
          border-radius: 8px;
          color: var(--text-primary);
          padding: 8px 12px;
          font-size: 12px;
          font-family: inherit;
          outline: none;
          transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .input:focus { border-color: rgba(69, 137, 255, 0.5); box-shadow: 0 0 12px rgba(69, 137, 255, 0.2); }
        select.input { cursor: pointer; }

        /* ===== GAUGES ===== */
        .h-bar { height: 8px; background: var(--bg-input); border-radius: 4px; overflow: hidden; }
        .h-bar-fill { height: 100%; border-radius: 4px; transition: width 0.4s ease; }
        .h-bar-green  { background: var(--success); }
        .h-bar-yellow { background: var(--warning); }
        .h-bar-red    { background: var(--danger); }

        /* ===== STAT ===== */
        .stat-num { font-size: 32px; font-weight: 700; text-shadow: 0 0 20px rgba(69, 137, 255, 0.2); }
        .stat-label { font-size: 12px; color: var(--text-secondary); letter-spacing: 0.05em; margin-top: 4px; }

        /* ===== PIPELINE ===== */
        .pipeline-strip { display: flex; align-items: center; overflow-x: auto; padding-bottom: 6px; gap: 0; scrollbar-width: thin; scrollbar-color: var(--border) transparent; }
        .pipe-node { flex-shrink: 0; width: 80px; border-radius: 8px; padding: 8px 6px 6px; cursor: pointer; border: 1px solid transparent; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); text-align: center; position: relative; overflow: hidden; }
        .pipe-node:hover { filter: brightness(1.3); transform: translateY(-2px); }
        .pipe-node-idle     { border-color: var(--border); background: rgba(13, 13, 26, 0.7); }
        .pipe-node-active   { border-color: #059669; background: rgba(6, 23, 14, 0.7); box-shadow: 0 0 15px rgba(16, 185, 129, 0.3); }
        .pipe-node-critical { border-color: var(--danger); background: rgba(26, 5, 5, 0.7); animation: pulse 1s infinite; box-shadow: 0 0 15px rgba(239, 68, 68, 0.3); }
        .pipe-node-selected { border-color: var(--ibm-granite) !important; background: rgba(13, 26, 46, 0.8) !important; animation: none !important; box-shadow: 0 0 20px rgba(69, 137, 255, 0.4); }
        .pipe-connector { color: var(--border); font-size: 14px; padding: 0 2px; flex-shrink: 0; }
        .pipe-dot { width: 6px; height: 6px; border-radius: 50%; margin: 4px auto 0; }
        .pipe-dot-idle     { background: #374151; }
        .pipe-dot-active   { background: #059669; box-shadow: 0 0 6px rgba(16, 185, 129, 0.5); }
        .pipe-dot-critical { background: var(--danger); animation: pulse 0.8s infinite; box-shadow: 0 0 6px rgba(239, 68, 68, 0.5); }

        /* ===== NAC WORKFLOW ===== */
        .nac-track { position: relative; display: flex; justify-content: space-between; align-items: center; padding: 24px 0 10px; }
        .nac-step { width: 64px; text-align: center; position: relative; z-index: 2; }
        .nac-step-circle { width: 36px; height: 36px; border-radius: 50%; border: 2px solid var(--border); background: var(--glass-bg); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; margin: 0 auto 6px; font-size: 11px; font-weight: 700; color: var(--text-secondary); transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1); box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3); }
        .nac-step-label { font-size: 8px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }
        .nac-step.nac-active .nac-step-circle { border-color: var(--ibm-granite); background: rgba(69,137,255,0.25); color: var(--ibm-granite); animation: pulse 1.2s infinite; box-shadow: 0 0 15px rgba(69, 137, 255, 0.4); }
        .nac-step.nac-pass .nac-step-circle   { border-color: var(--success); background: rgba(16,185,129,0.25); color: var(--success); box-shadow: 0 0 10px rgba(16, 185, 129, 0.3); }
        .nac-step.nac-fail .nac-step-circle   { border-color: var(--danger); background: rgba(239,68,68,0.25); color: var(--danger); box-shadow: 0 0 10px rgba(239, 68, 68, 0.3); }
        .nac-line { position: absolute; top: 42px; left: 32px; right: 32px; height: 2px; background: linear-gradient(90deg, var(--border), rgba(69, 137, 255, 0.2), var(--border)); z-index: 1; }
        .nac-figure { position: absolute; top: 14px; width: 24px; height: 24px; font-size: 18px; transition: left 0.6s cubic-bezier(0.4, 0, 0.2, 1); transform: translateX(-50%); z-index: 3; filter: drop-shadow(0 0 8px rgba(69, 137, 255, 0.5)); }

        /* ===== SANDBOX FILE TREE ===== */
        .file-tree { font-size: 12px; }
        .file-item { display: flex; align-items: center; gap: 6px; padding: 3px 6px; border-radius: 4px; cursor: pointer; transition: background 0.15s; }
        .file-item:hover { background: rgba(255,255,255,0.04); }
        .file-item.selected { background: rgba(69,137,255,0.12); border: 1px solid rgba(69,137,255,0.3); }
        .file-item.poisoned { border-left: 2px solid var(--warning); }
        .file-item.locked   { opacity: 0.7; }
        .file-indent { padding-left: 16px; }

        /* ===== AGENT FLEET ===== */
        .agent-fleet { max-width: 1440px; margin: 0 auto; color: #161616; }
        .agent-fleet-hero { display: flex; align-items: flex-end; justify-content: space-between; gap: 24px; padding: 4px 0 28px; border-bottom: 1px solid #dde1e6; }
        .agent-fleet-kicker { margin: 0 0 8px; color: #525252; font-size: 12px; font-weight: 600; letter-spacing: .02em; text-transform: uppercase; }
        .agent-fleet-title { margin: 0; color: #161616; font-size: 32px; line-height: 1.15; font-weight: 500; letter-spacing: -.02em; }
        .agent-fleet-subtitle { max-width: 720px; margin: 12px 0 0; color: #525252; font-size: 15px; line-height: 1.5; }
        .agent-fleet-posture { display: flex; align-items: center; gap: 12px; min-width: 232px; padding: 14px 16px; border: 1px solid #a6c8ff; background: #edf5ff; }
        .agent-fleet-posture-marker { width: 10px; height: 10px; border-radius: 50%; background: #0f62fe; flex: 0 0 auto; }
        .agent-fleet-posture small { display: block; color: #525252; font-size: 11px; }
        .agent-fleet-posture strong { display: block; margin-top: 2px; color: #161616; font-size: 16px; font-weight: 600; }
        .agent-fleet-metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1px; margin: 28px 0 24px; border: 1px solid #dde1e6; background: #dde1e6; }
        .agent-fleet-metric { min-height: 118px; padding: 18px 20px; background: #fff; display: flex; flex-direction: column; justify-content: space-between; }
        .agent-fleet-metric-label { color: #525252; font-size: 13px; }
        .agent-fleet-metric-value { color: #161616; font-size: 28px; line-height: 1; font-weight: 500; letter-spacing: -.02em; }
        .agent-fleet-metric-note { color: #525252; font-size: 12px; }
        .agent-fleet-metric--active .agent-fleet-metric-value { color: #0f62fe; }
        .agent-fleet-metric--running .agent-fleet-metric-value { color: #8a6d00; }
        .agent-fleet-metric--completed .agent-fleet-metric-value { color: #198038; }
        .agent-fleet-metric--queue .agent-fleet-metric-value { color: #525252; }
        .agent-fleet-workspace { display: grid; grid-template-columns: minmax(0, 1.65fr) minmax(300px, .85fr); gap: 24px; align-items: start; }
        .agent-panel { border: 1px solid #dde1e6; background: #fff; }
        .agent-panel + .agent-panel { margin-top: 24px; }
        .agent-panel-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding: 20px 20px 16px; border-bottom: 1px solid #dde1e6; }
        .agent-panel-title { margin: 0; color: #161616; font-size: 18px; font-weight: 500; letter-spacing: -.01em; }
        .agent-panel-description { margin: 5px 0 0; color: #525252; font-size: 13px; line-height: 1.45; }
        .agent-panel-count { color: #0f62fe; font-family: "IBM Plex Mono", "Consolas", monospace; font-size: 12px; font-weight: 600; white-space: nowrap; }
        .agent-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(190px, 1fr)); gap: 1px; max-height: 650px; overflow-y: auto; background: #dde1e6; }
        .agent-node { min-height: 132px; padding: 16px; background: #fff; border: 0; border-left: 3px solid #8d8d8d; border-radius: 0; cursor: default; overflow: hidden; position: relative; transition: background .15s ease, box-shadow .15s ease; }
        .agent-node::before { display: none; }
        .agent-node:hover { background: #f4f4f4; border-color: #0f62fe; box-shadow: inset 0 0 0 1px #0f62fe; transform: none; }
        .agent-node--running { border-left-color: #f1c21b; }
        .agent-node--completed { border-left-color: #24a148; }
        .agent-node--failed { border-left-color: #da1e28; }
        .agent-node-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; }
        .agent-name { color: #161616; font-family: "IBM Plex Mono", "Consolas", monospace; font-size: 12px; font-weight: 600; letter-spacing: -.01em; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .agent-state { display: inline-flex; align-items: center; gap: 5px; color: #525252; font-size: 10px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase; white-space: nowrap; }
        .agent-state-dot { position: static; width: 7px; height: 7px; border-radius: 50%; box-shadow: none; }
        .dot-idle { background: #8d8d8d; }
        .dot-running { background: #f1c21b; animation: none; box-shadow: none; }
        .dot-completed { background: #24a148; box-shadow: none; }
        .dot-failed { background: #da1e28; box-shadow: none; }
        .agent-state--running { color: #684e00; }
        .agent-state--completed { color: #0e6027; }
        .agent-state--failed { color: #a2191f; }
        .agent-node-description { min-height: 34px; margin: 10px 0 12px; color: #525252; font-size: 11px; line-height: 1.45; }
        .agent-node-meta { display: flex; align-items: center; justify-content: space-between; gap: 8px; color: #525252; font-size: 10px; }
        .agent-category { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-transform: uppercase; letter-spacing: .04em; }
        .agent-model { padding: 2px 5px; border: 1px solid #a6c8ff; color: #0043ce; background: #edf5ff; font-family: "IBM Plex Mono", "Consolas", monospace; font-size: 9px; font-weight: 600; white-space: nowrap; }
        .agent-model--heavy { border-color: #d4bbff; color: #6929c4; background: #f6f2ff; }
        .agent-work-counts { display: flex; gap: 10px; margin-top: 10px; color: #525252; font-family: "IBM Plex Mono", "Consolas", monospace; font-size: 10px; }
        .agent-work-counts strong { color: #198038; font-weight: 600; }
        .agent-work-counts .agent-fail-count { color: #a2191f; }
        .agent-empty { grid-column: 1 / -1; padding: 48px 24px; color: #525252; background: #fff; font-size: 13px; text-align: center; }
        .agent-composer { padding: 20px; display: flex; flex-direction: column; gap: 12px; }
        .agent-form-label { color: #525252; font-size: 12px; font-weight: 600; }
        .agent-fleet .input { min-height: 40px; padding: 0 12px; border: 1px solid #8d8d8d; border-radius: 0; background: #fff; color: #161616; box-shadow: none; font-size: 13px; }
        .agent-fleet .input:focus { outline: 2px solid #0f62fe; outline-offset: 2px; border-color: #0f62fe; box-shadow: none; }
        .agent-submit { justify-content: center; margin-top: 4px; border-radius: 0; }
        .agent-task-feedback { margin: 0 20px 20px; padding: 12px; border-left: 3px solid #0f62fe; background: #edf5ff; color: #161616; font-size: 12px; line-height: 1.5; }
        .agent-task-feedback--error { border-left-color: #da1e28; background: #fff1f1; }
        .agent-task-feedback__label { color: #525252; font-size: 11px; font-weight: 600; }
        .agent-task-feedback__id { color: #0043ce; font-family: "IBM Plex Mono", "Consolas", monospace; font-size: 11px; }
        .agent-task-feedback__pending { margin-top: 5px; color: #684e00; }
        .agent-task-feedback__result { margin-top: 5px; }
        .agent-distribution { padding: 4px 20px 14px; }
        .agent-distribution-row { display: grid; grid-template-columns: 40px minmax(0, 1fr); gap: 12px; align-items: center; padding: 13px 0; border-bottom: 1px solid #e0e0e0; }
        .agent-distribution-row:last-child { border-bottom: 0; }
        .agent-distribution-count { color: #161616; font-size: 20px; font-weight: 500; text-align: right; }
        .agent-distribution-label { display: flex; justify-content: space-between; gap: 10px; color: #525252; font-size: 12px; }
        .agent-distribution-bar { height: 6px; margin-top: 7px; overflow: hidden; background: #e0e0e0; }
        .agent-distribution-fill { height: 100%; background: #0f62fe; }
        .agent-distribution-fill--soc { background: #24a148; }
        .agent-distribution-fill--pentest { background: #f1c21b; }
        @media (max-width: 1100px) { .agent-fleet-workspace { grid-template-columns: 1fr; } }
        @media (max-width: 800px) { .agent-fleet-hero { align-items: flex-start; flex-direction: column; } .agent-fleet-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
        @media (max-width: 560px) { .agent-fleet-title { font-size: 28px; } .agent-fleet-metrics { grid-template-columns: 1fr; } .agent-grid { grid-template-columns: 1fr; max-height: none; } .agent-panel-header { align-items: flex-start; flex-direction: column; } }

        /* ===== AUDIT CHAIN ===== */
        .chain-blocks { display: flex; overflow-x: auto; gap: 0; padding: 8px 0; scrollbar-width: thin; }
        .chain-block { flex-shrink: 0; width: 120px; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; padding: 8px; cursor: pointer; transition: all 0.2s; }
        .chain-block:hover, .chain-block.selected { border-color: var(--ibm-granite); box-shadow: 0 0 20px rgba(69, 137, 255, 0.3); transform: translateY(-2px); }
        .chain-arrow { display: flex; align-items: center; color: var(--ibm-granite); font-size: 16px; padding: 0 4px; flex-shrink: 0; filter: drop-shadow(0 0 4px rgba(69, 137, 255, 0.5)); }
        .chain-hash { font-size: 9px; font-family: monospace; color: #60a5fa; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-shadow: 0 0 8px rgba(96, 165, 250, 0.3); }
        .chain-event { font-size: 10px; font-weight: 600; color: var(--text-primary); }

        /* ===== VERSION TIMELINE ===== */
        .version-timeline { display: flex; flex-direction: column; gap: 0; }
        .version-entry { display: flex; gap: 12px; padding: 6px 0; border-bottom: 1px solid var(--border); cursor: pointer; transition: background 0.15s; }
        .version-entry:hover, .version-entry.selected { background: rgba(69,137,255,0.06); }
        .version-dot-col { display: flex; flex-direction: column; align-items: center; gap: 0; width: 20px; }
        .version-dot { width: 10px; height: 10px; border-radius: 50%; border: 2px solid var(--ibm-granite); background: var(--bg-primary); flex-shrink: 0; }
        .version-line { flex: 1; width: 2px; background: var(--border); }
        .version-content { flex: 1; padding-bottom: 6px; }
        .version-num { font-size: 11px; font-weight: 700; color: var(--ibm-granite); }
        .version-meta { font-size: 10px; color: var(--text-secondary); }
        .version-preview { font-size: 10px; font-family: monospace; color: #94a3b8; margin-top: 2px; }

        /* ===== MODAL ===== */
        .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(4px); z-index: 200; display: flex; align-items: center; justify-content: center; }
        .modal-box { background: var(--glass-bg); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border: 1px solid var(--glass-border); border-radius: 16px; padding: 28px; max-width: 480px; width: 90%; box-shadow: 0 20px 60px rgba(0,0,0,0.5), 0 0 40px rgba(69, 137, 255, 0.15); animation: slideIn 0.3s ease-out; position: relative; overflow: hidden; }
        .modal-box::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px; background: linear-gradient(90deg, transparent, rgba(69, 137, 255, 0.4), transparent); }
        .modal-title { font-size: 16px; font-weight: 700; color: var(--text-primary); margin-bottom: 12px; }
        .modal-close { float: right; cursor: pointer; color: var(--text-secondary); font-size: 18px; line-height: 1; }

        /* ===== TABS ===== */
        .tabs { display: flex; gap: 2px; border-bottom: 1px solid var(--border); margin-bottom: 14px; }
        .tab-btn { padding: 7px 14px; font-size: 11px; font-weight: 600; color: var(--text-secondary); background: none; border: none; border-bottom: 2px solid transparent; cursor: pointer; text-transform: uppercase; letter-spacing: 0.07em; transition: all 0.15s; }
        .tab-btn:hover:not(.active) { color: var(--text-primary); }
        .tab-btn.active { color: var(--ibm-granite); border-bottom-color: var(--ibm-granite); }

        /* ===== CSF / FRAMEWORK ===== */
        .csf-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; }
        .csf-col { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; padding: 8px; }
        .csf-title { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 6px; }
        .csf-identify { color: #60a5fa; }
        .csf-protect  { color: #4ade80; }
        .csf-detect   { color: #fbbf24; }
        .csf-respond  { color: #f87171; }
        .csf-recover  { color: #a78bfa; }
        .csf-item { font-size: 10px; color: var(--text-secondary); padding: 2px 0; border-bottom: 1px solid rgba(42,42,62,0.5); }
        .fw-row { display: flex; gap: 8px; align-items: baseline; padding: 5px 0; border-bottom: 1px solid rgba(42,42,62,0.5); }
        .fw-id { font-family: monospace; font-size: 11px; color: #60a5fa; min-width: 80px; }
        .fw-desc { font-size: 11px; color: var(--text-secondary); flex: 1; }
        .fw-src { font-size: 10px; color: #4b5563; }
        .kc-grid { display: grid; grid-template-columns: repeat(7, 1fr); gap: 6px; }
        .kc-stage { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; padding: 8px; text-align: center; }
        .kc-intercepted { border-color: #059669; }
        .kc-stage-name { font-size: 10px; font-weight: 700; color: var(--text-secondary); margin-bottom: 4px; }
        .kc-intercepted .kc-stage-name { color: #4ade80; }
        .kc-badge { font-size: 9px; padding: 1px 5px; border-radius: 3px; }
        .kc-badge-int  { background: #064e3b; color: #4ade80; }
        .kc-badge-pass { background: var(--bg-panel); color: #4b5563; }
        .technique-id { color: #60a5fa; font-family: monospace; font-size: 11px; }
        .tactic-tag { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; background: var(--bg-secondary); color: var(--text-secondary); }

        /* ===== REDUCED MOTION ===== */
        @media (prefers-reduced-motion: reduce) {
          *, *::before, *::after { animation: none !important; transition: none !important; }
        }

        /* ===== Astartis assurance overview ===== */
        .overview-page { max-width: 1440px; margin: 0 auto; }
        .overview-hero { display:flex; justify-content:space-between; gap:24px; align-items:flex-end; padding:8px 0 28px; border-bottom:1px solid #dde1e6; }
        .eyebrow { color:#525252; font-size:12px; font-weight:600; letter-spacing:.02em; margin:0 0 8px; text-transform:uppercase; }
        .overview-hero h1 { color:#161616; font-size:32px; line-height:1.15; letter-spacing:-.02em; margin:0; }
        .overview-subtitle { color:#525252; font-size:15px; max-width:720px; margin:12px 0 0; }
        .posture-badge { display:flex; align-items:center; gap:10px; padding:12px 16px; min-width:170px; border:1px solid #dde1e6; background:#fff; }
        .posture-badge small { display:block; color:#525252; font-size:11px; }
        .posture-badge strong { color:#161616; font-size:16px; }
        .posture-dot, .priority-marker { width:10px; height:10px; border-radius:50%; flex:0 0 auto; }
        .posture-low .posture-dot, .marker-good { background:#24a148; }
        .posture-medium .posture-dot, .marker-warning { background:#f1c21b; }
        .posture-high .posture-dot, .posture-critical .posture-dot, .marker-critical { background:#da1e28; }
        .marker-neutral { background:#8d8d8d; }
        .metric-grid { display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:1px; background:#dde1e6; border:1px solid #dde1e6; margin:28px 0; }
        .metric-card { background:#fff; padding:20px; min-height:126px; display:flex; flex-direction:column; justify-content:space-between; }
        .metric-label { color:#525252; font-size:13px; }
        .metric-value { color:#161616; font-size:24px; line-height:1.15; font-weight:500; }
        .metric-note { font-size:12px; }
        .is-good { color:#198038; } .is-warning { color:#8a6d00; } .is-critical { color:#da1e28; } .is-muted { color:#525252; }
        .overview-grid { display:grid; grid-template-columns:1.25fr 1fr; gap:24px; margin-bottom:24px; }
        .overview-grid-bottom { grid-template-columns:1fr 1fr; }
        .section-card { border:1px solid #dde1e6; background:#fff; padding:24px; }
        .section-card-head { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; margin-bottom:16px; }
        .section-card h2 { margin:0; color:#161616; font-size:20px; font-weight:500; letter-spacing:-.01em; }
        .capture-description, .compact-card p { color:#525252; font-size:14px; line-height:1.5; }
        .adapter-select-label { display:flex; flex-direction:column; gap:6px; width:min(100%, 480px); margin-top:18px; color:#525252; font-size:12px; font-weight:600; }
        .adapter-select { appearance:auto; border:1px solid #8d8d8d; border-radius:0; background:#fff; color:#161616; min-height:40px; padding:0 10px; font-size:14px; }
        .adapter-select:focus { outline:2px solid #0f62fe; outline-offset:2px; }
        .capture-actions { display:flex; align-items:center; flex-wrap:wrap; gap:14px; margin-top:22px; }
        .status-chip { font-size:12px; font-weight:600; padding:4px 8px; white-space:nowrap; }
        .status-good { color:#0e6027; background:#defbe6; } .status-warning { color:#684e00; background:#fff1c2; } .status-neutral { color:#525252; background:#e0e0e0; }
        .inline-alert, .capture-feedback { margin:14px 0 0; padding:10px 12px; font-size:12px; line-height:1.4; }
        .inline-alert, .capture-feedback-error { color:#a2191f; background:#fff1f1; border-left:3px solid #da1e28; }
        .priority-list { border-top:1px solid #dde1e6; }
        .priority-row { display:flex; gap:12px; align-items:flex-start; padding:16px 0; border-bottom:1px solid #dde1e6; }
        .priority-row strong { color:#161616; font-size:14px; }
        .priority-row p { color:#525252; font-size:13px; margin:4px 0 0; }
        .btn { border-radius:0; min-height:40px; padding:0 16px; font-weight:500; }
        .btn-primary { background:#0f62fe; border-color:#0f62fe; color:#fff; }
        .btn-primary:hover { background:#0043ce; border-color:#0043ce; }
        .btn-secondary { background:#fff; border:1px solid #0f62fe; color:#0f62fe; }
        .text-button { background:transparent; border:0; padding:0; color:#0f62fe; font-size:14px; cursor:pointer; text-align:left; }
        .text-button:hover { color:#0043ce; text-decoration:underline; }
        .capture-card { box-shadow:none; }
        @media (max-width: 1024px) { .metric-grid { grid-template-columns:repeat(2, minmax(0,1fr)); } .overview-grid { grid-template-columns:1fr; } .app-dock { width:176px; } .terminal-workspace-hero { align-items:flex-start; flex-direction:column; } .runtime-settings-grid { grid-template-columns:1fr; } }
        @media (max-width: 720px) { .topbar { padding:0 12px; } .topbar-center, .topbar-pills .pill-clock, .topbar-pills .topbar-evidence { display:none; } .desktop { flex-direction:column; } .app-dock { width:auto; flex-direction:row; overflow-x:auto; padding:6px 8px; border-right:0; border-bottom:1px solid #dde1e6; } .dock-item { min-width:112px; height:36px; } .main-area { padding:20px 16px; } .overview-hero { align-items:flex-start; flex-direction:column; } .metric-grid { grid-template-columns:1fr; } .overview-hero h1, .terminal-workspace-title { font-size:28px; } .terminal-status-grid { grid-template-columns:1fr; } .terminal-console-toolbar { align-items:flex-start; flex-direction:column; } .terminal-console-filters { justify-content:flex-start; } .terminal-line { grid-template-columns:1fr; gap:2px; padding:8px 16px; } .terminal-dock { padding:0 16px; } .terminal-dock-status { display:none; } .runtime-row { grid-template-columns:1fr; gap:8px; } .runtime-row-value { max-width:none; text-align:left; } }

        /* ===== SCROLLBAR ===== */
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
      </style>
      <div class="scanline-overlay"></div>


    <%!-- ===== TOP BAR ===== --%>
    <div class="topbar">
      <button class="topbar-logo" phx-click="switch_app" phx-value-app="overview" style="background:none;border:none;cursor:pointer;" title="Return to overview">
        <svg class="topbar-diamond" viewBox="0 0 24 24" fill="none">
          <polygon points="12,2 22,9 18,20 6,20 2,9" fill="#4589ff" stroke="#7eb3ff" stroke-width="1"/>
          <text x="12" y="15" text-anchor="middle" fill="white" font-size="8" font-weight="bold">AI</text>
        </svg>
        <span class="topbar-brand-suite">
          <span class="topbar-brand">ASTARTIS</span>
          <span class="topbar-brand-divider">&times;</span>
          <span class="topbar-brand-codex">CODEX</span>
        </span>
      </button>

      <div class="topbar-center">LOCAL SECURITY EVIDENCE CONTROL PLANE</div>

      <div style="display:flex;align-items:center;gap:10px;">
        <span class="pill" style="background:#defbe6;color:#0e6027;border-color:#a7f0ba;font-size:10px;cursor:default;">
          <span style="font-size:10px;font-weight:700;letter-spacing:.04em;">AI</span> <%= length(@agent_statuses) %> AGENTS ACTIVE
        </span>
      </div>

      <div class="topbar-pills">
        <span class={"pill topbar-evidence topbar-evidence--#{capture_tone}"}>Telemetry: <%= capture_label %></span>
        <span class={"pill topbar-evidence topbar-evidence--#{evidence_tone}"}>Evidence: <%= evidence_label %></span>
        <button phx-click="switch_app" phx-value-app="reports"
                class={"pill pill-#{@threat_tier_name}"} style="background:none;border-style:solid;cursor:pointer;">
          Threat: <%= @threat_tier_name %>
        </button>

        <span class="pill pill-clock mono" id="topbar-clock" phx-hook="Clock">
          <%= DateTime.utc_now() |> Calendar.strftime("%H:%M:%S UTC") %>
        </span>

        <button phx-click="toggle_worm_modal"
                class={"pill #{if @worm_locked, do: "pill-worm-locked", else: "pill-worm-normal"}"}
                style="cursor:pointer;">
          <%= if @worm_locked, do: "WORM LOCKED", else: "WORM NORMAL" %>
        </button>
      </div>
    </div>

    <%!-- ===== DESKTOP ===== --%>
    <div class="desktop">

      <%!-- APP DOCK --%>
      <div class="app-dock">
        <%= for {icon, app, label, badge} <- dock_items(assigns) do %>
          <button phx-click="switch_app" phx-value-app={app}
                  class={"dock-item #{if @active_app == app, do: "active", else: ""}"}
                  style="background:none;border-style:solid;cursor:pointer;"
                  title={label}>
            <%= if badge > 0 do %><span class="dock-badge"><%= badge %></span><% end %>
            <span class="dock-icon" aria-hidden="true"><%= icon %></span>
            <span class="dock-label"><%= label %></span>
          </button>
        <% end %>
      </div>

      <%!-- MAIN CONTENT AREA --%>
      <div class="main-area">

        <%= case @active_app do %>
          <% "overview" -> %> <%= render_overview(assigns) %>
          <% "network" -> %> <%= render_network(assigns) %>
          <% "defense" -> %> <%= render_defense(assigns) %>
          <% "agents"  -> %> <%= render_agents(assigns) %>
          <% "sandbox" -> %> <%= render_sandbox(assigns) %>
          <% "pipeline"-> %> <%= render_pipeline(assigns) %>
          <% "nac"     -> %> <%= render_nac(assigns) %>
          <% "codex"   -> %> <%= render_codex(assigns) %>
          <% "terminal"-> %> <%= render_terminal(assigns) %>
          <% "reports" -> %> <%= render_reports(assigns) %>
          <% "audit"   -> %> <%= render_audit(assigns) %>
          <% "settings"-> %> <%= render_settings(assigns) %>
          <% _         -> %> <%= render_network(assigns) %>
        <% end %>

      </div><%!-- /main-area --%>
    </div><%!-- /desktop --%>

    <%!-- ===== TERMINAL DOCK ===== --%>
    <%= if @terminal_dock_visible do %>
      <div class="terminal-dock">
        <button class="terminal-dock-open" phx-click="switch_app" phx-value-app="terminal" type="button">
          <span>Terminal</span>
          <span class="terminal-dock-count"><%= length(@terminal_lines) %> events</span>
        </button>
        <div class="terminal-dock-status" aria-label="Current evidence state">
          <span class={"terminal-state-chip terminal-state-chip--#{capture_tone}"}>Telemetry: <%= capture_label %></span>
          <span class={"terminal-state-chip terminal-state-chip--#{evidence_tone}"}>Evidence: <%= evidence_label %></span>
          <span>Window: <%= @evidence_window_label %></span>
          <span><%= terminal_latest_label(@terminal_lines) %></span>
        </div>
        <button class="terminal-dock-link" phx-click="switch_app" phx-value-app="terminal" type="button">Open workspace</button>
      </div>
    <% end %>

    <%!-- ===== MODALS ===== --%>
    <%= if @show_about_modal do %>
      <div class="modal-overlay" phx-click="close_modal">
        <div class="modal-box" phx-click-away="close_modal">
          <button phx-click="close_modal" class="modal-close" style="background:none;border:none;">×</button>
          <div class="modal-title">
            <svg width="32" height="32" viewBox="0 0 24 24" style="vertical-align:middle;margin-right:8px;">
              <polygon points="12,2 22,9 18,20 6,20 2,9" fill="#4589ff" stroke="#7eb3ff" stroke-width="1"/>
              <text x="12" y="15" text-anchor="middle" fill="white" font-size="8" font-weight="bold">AI</text>
            </svg>
            About Astartis
          </div>
          <p style="color:var(--text-secondary);font-size:13px;margin-bottom:12px;">
            <strong style="color:var(--ibm-granite);">Local AI inference</strong>
            — running locally via Ollama, zero cloud cost.
          </p>
          <p style="color:var(--text-secondary);font-size:13px;margin-bottom:8px;">
            <%= length(@agent_statuses) %> autonomous security agents · OMIDAX + DIBANET frameworks · Full Zero Trust pipeline
          </p>
          <p style="font-size:12px;color:#4b5563;">
            Built for OpenAI Build Week · Developer Tools · local-first security assurance
          </p>
          <div style="margin-top:16px;padding:8px;background:var(--bg-secondary);border-radius:6px;font-size:11px;font-family:monospace;color:var(--text-secondary);">
            Models: local fast tier | local deep-analysis tier<br/>
            Backend: C++ + Elixir/Phoenix LiveView<br/>
            Status: 5/5 protection checks pass · 23/23 tests pass
          </div>
        </div>
      </div>
    <% end %>

    <%= if @show_worm_modal do %>
      <div class="modal-overlay" phx-click="close_modal">
        <div class="modal-box" phx-click-away="close_modal">
          <button phx-click="close_modal" class="modal-close" style="background:none;border:none;">×</button>
          <div class="modal-title">🔒 WORM Lockdown Control</div>
          <div style="margin-bottom:12px;">
            <span class={if @worm_locked, do: "worm-locked", else: "worm-normal"}>
              <%= if @worm_locked, do: "LOCKED", else: "NORMAL" %>
            </span>
            <span style="margin-left:8px;font-size:12px;color:var(--text-secondary);">
              Activations: <%= @worm_lock_count %>
            </span>
          </div>
          <%= if @worm_reason != "" do %>
            <p style="font-size:12px;color:var(--text-secondary);margin-bottom:12px;">
              Reason: <span class="mono" style="color:#fca5a5;"><%= @worm_reason %></span>
            </p>
          <% end %>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <%= if @worm_locked do %>
              <button class="btn btn-ghost" phx-click="worm_unlock" style="cursor:pointer;">
                🔓 Request Unlock
              </button>
            <% end %>
            <button class="btn btn-danger" phx-click="close_modal" style="cursor:pointer;"
                    onclick="this.closest('.modal-overlay').remove()">
              Close
            </button>
          </div>
          <%!-- 12-Eye Unlock --%>
          <%= if @worm_locked and @unlock_approvers != [] do %>
            <div style="margin-top:14px;border-top:1px solid var(--border);padding-top:12px;">
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.07em;color:var(--text-secondary);margin-bottom:8px;">
                12-Eye Unlock — <%= @unlock_votes_collected %>/<%= @unlock_threshold %> votes
              </div>
              <%= for ap <- @unlock_approvers do %>
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
                  <span style={"font-size:10px;padding:1px 6px;border-radius:3px;#{if ap["voted"], do: "background:#064e3b;color:#6ee7b7;", else: "background:var(--bg-secondary);color:#4b5563;"}"}>
                    <%= if ap["voted"], do: "✓", else: "○" %>
                  </span>
                  <span class="mono" style="font-size:11px;"><%= ap["name"] %></span>
                  <%= if not ap["voted"] and @unlock_state == "COLLECTING" do %>
                    <button class="btn btn-ghost btn-sm" phx-click="cast_unlock_vote"
                            phx-value-approver={ap["name"]} style="margin-left:auto;cursor:pointer;">
                      Vote
                    </button>
                  <% end %>
                </div>
              <% end %>
            </div>
          <% end %>
        </div>
      </div>
    <% end %>

    </div><%!-- /os-root --%>
    """
  end


  # ---------------------------------------------------------------------------
  # App: Security overview
  # ---------------------------------------------------------------------------

  defp render_overview(assigns) do
    ~H"""
    <div class="overview-page anim-fade">
      <div class="overview-hero">
        <div>
          <p class="eyebrow">Security operations</p>
          <h1>Know what needs attention.</h1>
          <p class="overview-subtitle">Astartis brings live network assurance, Zero Trust evidence, and 77-agent health into one operator view.</p>
        </div>
        <div class={"posture-badge posture-#{String.downcase(@threat_tier_name)}"}>
          <span class="posture-dot"></span>
          <div><small>Current posture</small><strong><%= @threat_tier_name %></strong></div>
        </div>
      </div>

      <div class="metric-grid">
        <div class="metric-card">
          <span class="metric-label">Network sensor</span>
          <strong class="metric-value"><%= if @packet_capture_running, do: "Active", else: "Off" %></strong>
          <span class={"metric-note #{if @packet_capture_running, do: "is-good", else: "is-muted"}"}>
            <%= if @packet_capture_running, do: "#{@packet_windows} windows inspected", else: "Start live Npcap capture" %>
          </span>
        </div>
        <div class="metric-card">
          <span class="metric-label">Zero Trust</span>
          <strong class="metric-value"><%= if @worm_locked, do: "Restricted", else: "Protected" %></strong>
          <span class={"metric-note #{if @worm_locked, do: "is-warning", else: "is-good"}"}><%= if @worm_locked, do: "WORM recovery protocol is active", else: "Continuous policy enforcement" %></span>
        </div>
        <div class="metric-card">
          <span class="metric-label">Evidence integrity</span>
          <strong class="metric-value"><%= if @chain_valid, do: "Verified", else: "Review" %></strong>
          <span class={"metric-note #{if @chain_valid, do: "is-good", else: "is-critical"}"}><%= @chain_length %> immutable audit entries</span>
        </div>
        <div class="metric-card">
          <span class="metric-label">Agent fleet</span>
          <strong class="metric-value"><%= length(@agent_statuses) %> loaded</strong>
          <span class="metric-note is-muted"><%= @agent_queue_depth %> tasks in queue</span>
        </div>
      </div>

      <div class="overview-grid">
        <section class="section-card capture-summary">
          <div class="section-card-head">
            <div>
              <p class="eyebrow">Network assurance</p>
              <h2>Live packet capture</h2>
            </div>
            <span class={"status-chip #{if @packet_capture_running and @packet_capture_mode == "live", do: "status-good", else: if(@packet_capture_mode == "synthetic", do: "status-warning", else: "status-neutral")}"}>
              <%= cond do %>
                <% @packet_capture_running and @packet_capture_mode == "live" -> %>Live Npcap
                <% @packet_capture_mode == "synthetic" -> %>Demo mode
                <% @capture_action_state == "starting" -> %>Starting
                <% true -> %>Not collecting
              <% end %>
            </span>
          </div>
          <p class="capture-description">
            <%= if @packet_capture_running and @packet_capture_mode == "live" do %>
              Inspecting local traffic through <span class="mono"><%= @packet_capture_adapter %></span>. No packet payloads leave this device.
            <% else %>
              Start this only when you want Astartis to analyse your local adapter. It feeds the existing entropy and rule-engine pipeline.
            <% end %>
          </p>
          <%= if not @packet_capture_running and @capture_adapters != [] do %>
            <form phx-change="packet_capture_adapter_select">
              <label class="adapter-select-label">
                Capture adapter
                <select name="adapter" class="adapter-select">
                  <option value="">Automatic selection</option>
                  <%= for adapter <- @capture_adapters, adapter["up"] and not adapter["loopback"] do %>
                    <option value={adapter["name"]} selected={@capture_adapter_choice == adapter["name"]}>
                      <%= if adapter["description"] in [nil, ""], do: adapter["name"], else: adapter["description"] %>
                    </option>
                  <% end %>
                </select>
              </label>
            </form>
          <% end %>
          <%= if @capture_error do %><p class="inline-alert"><%= @capture_error %></p><% end %>
          <div class="capture-actions">
            <%= if @packet_capture_running do %>
              <button class="btn btn-secondary" phx-click="packet_capture_stop">Stop capture</button>
            <% else %>
              <button data-testid="live-capture-start" class="btn btn-primary" phx-click="packet_capture_start" disabled={@capture_action_state == "starting"}><%= if @capture_action_state == "starting", do: "Starting…", else: "Start live capture" %></button>
            <% end %>
            <button class="text-button" phx-click="switch_app" phx-value-app="network">View network details</button>
          </div>
        </section>

        <section class="section-card">
          <div class="section-card-head"><div><p class="eyebrow">Priority queue</p><h2>What to review</h2></div><button class="text-button" phx-click="switch_app" phx-value-app="defense">Open detections</button></div>
          <div class="priority-list">
            <div class="priority-row"><span class={"priority-marker #{if @packet_capture_running, do: "marker-good", else: "marker-neutral"}"}></span><div><strong>Network telemetry</strong><p><%= if @packet_capture_running, do: "Sensor is producing #{@packet_windows} entropy windows.", else: "Live capture is not running." %></p></div></div>
            <div class="priority-row"><span class={"priority-marker #{if @worm_locked, do: "marker-warning", else: "marker-good"}"}></span><div><strong>Recovery controls</strong><p><%= if @worm_locked, do: "WORM lockdown is active and awaits approved recovery.", else: "WORM protection is available." %></p></div></div>
            <div class="priority-row"><span class={"priority-marker #{if @chain_valid, do: "marker-good", else: "marker-critical"}"}></span><div><strong>Audit evidence</strong><p><%= if @chain_valid, do: "Hash chain verified across #{@chain_length} entries.", else: "Evidence integrity requires review." %></p></div></div>
          </div>
        </section>
      </div>

      <div class="overview-grid overview-grid-bottom">
        <section class="section-card compact-card">
          <p class="eyebrow">Access assurance</p><h2>NAC and Zero Trust</h2>
          <p>Test a device admission decision, inspect trust evidence, and trace policy without touching production controls.</p>
          <button class="text-button" phx-click="switch_app" phx-value-app="nac">Open access controls</button>
        </section>
        <section class="section-card compact-card">
          <p class="eyebrow">Developer control plane</p><h2>Codex-ready evidence</h2>
          <p>Give Codex safe, local visibility into policy evidence, agent health, NAC, Zero Trust, and Proof Mode.</p>
          <button class="text-button" phx-click="switch_app" phx-value-app="codex">Open developer control plane</button>
        </section>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # App: Network Monitor

  defp render_network(assigns) do
    ~H"""
    <div class="anim-fade">
      <div class="card capture-card" style={"border-left:4px solid #{if @packet_capture_running, do: "#24a148", else: if(@capture_action_state == "error", do: "#da1e28", else: "#8d8d8d")};margin-bottom:14px;"}>
        <div style="display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;">
          <div>
            <div class="card-title" style="margin-bottom:3px;">Live Npcap sensor</div>
            <div style="font-size:12px;color:var(--text-secondary);">
              <%= if @packet_capture_running do %>
                <strong style="color:#42be65;">CAPTURING <%= String.upcase(@packet_capture_mode) %></strong>
                &nbsp;&middot;&nbsp; <span class="mono"><%= @packet_capture_adapter %></span>
                &nbsp;&middot;&nbsp; <%= @packet_windows %> entropy windows
              <% else %>
                <strong>OFF</strong> — no packet data is collected until you start it.
              <% end %>
            </div>
            <div style="font-size:10px;color:var(--text-secondary);margin-top:5px;">Local metadata analysis only: Astartis measures entropy windows and audits decisions; it does not upload packet payloads.</div>
            <%= if @capture_error do %>
              <div class="capture-feedback capture-feedback-error"><%= @capture_error %></div>
            <% end %>
          </div>
          <%= if @packet_capture_running do %>
            <button class="btn btn-danger" phx-click="packet_capture_stop" style="cursor:pointer;">Stop capture</button>
          <% else %>
            <button class="btn btn-primary" phx-click="packet_capture_start" disabled={@capture_action_state == "starting"} style="cursor:pointer;">
              <%= if @capture_action_state == "starting", do: "Starting…", else: "Start live capture" %>
            </button>
          <% end %>
        </div>
      </div>
      <div class="section-header">
        📡 Network Monitor — Live Threat Analysis
        <span class="granite-badge">LOCAL AI</span>
      </div>
      <div class="grid-2">
        <%!-- Left: Packet flow + chaos --%>
        <div>
          <div class="card glow">
            <div class="card-title">Live Packet Flow <span style="color:#475569;font-size:9px;margin-left:4px;">(entropy coloured)</span></div>
            <div id="packet-flow" phx-hook="PacketFlow"
                 class="mono" style="font-size:13px;letter-spacing:2px;min-height:40px;word-break:break-all;color:#4ade80;">
              ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
            </div>
            <div style="margin-top:8px;display:flex;gap:10px;font-size:10px;color:var(--text-secondary);">
              <span style="color:#4ade80;">░ low entropy</span>
              <span style="color:#fbbf24;">▒▓ medium</span>
              <span style="color:#f87171;">█ high / C2</span>
            </div>
          </div>

          <%!-- Entropy timeline: measured packet windows only. --%>
          <div class="card">
            <div class="card-title">Entropy Timeline <span style="color:#525252;font-size:9px;margin-left:4px;">(measured packet windows)</span></div>
            <div class="chaos-canvas-container">
              <canvas id="chaos-canvas" phx-hook="ChaosCanvas" data-threat={@threat_tier} style="width:100%;height:200px;display:block;"></canvas>
            </div>
            <div style="display:flex;justify-content:space-between;margin-top:8px;font-size:11px;">
              <span style="color:var(--text-secondary);">K-Score: <%= Float.round(@chaos_K * 100, 1) %>%</span>
              <span class={"font-mono #{if @threat_tier == "CRITICAL", do: "text-red-400 animate-pulse", else: "text-gray-400"}"}><%= @threat_tier %></span>
            </div>
          </div>

          <div class="card">
            <div class="card-title">Chaos Score (K) — 0-1 Test</div>
            <div style="display:flex;align-items:center;gap:16px;">
              <div>
                <div class={"stat-num #{if @chaos_anomalous, do: "text-red", else: "text-green"}"}
                     style={"color:#{if @chaos_anomalous, do: "#f87171", else: "#4ade80"};"}>
                  <%= :erlang.float_to_binary(@chaos_K + 0.0, [{:decimals, 4}]) %>
                </div>
                <div class="stat-label">K value (0=regular 1=chaotic)</div>
                <div class="stat-label">Windows: <%= @chaos_windows %></div>
                <%= if @chaos_anomalous do %>
                  <span class="badge badge-red" style="margin-top:4px;animation:pulse 1s infinite;">⚠ ANOMALOUS</span>
                <% end %>
              </div>
              <div style="flex:1;">
                <%= Phoenix.HTML.raw(chaos_svg_string(@chaos_history)) %>
              </div>
            </div>
          </div>
        </div>

        <%!-- Right: Gauges + Status --%>
        <div>
          <div class="card">
            <div class="card-title">Entropy Level</div>
            <div style="margin-bottom:6px;">
              <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px;">
                <span>K-Score</span>
                <span style={"color:#{k_color(@chaos_K)};"}>
                  <%= Float.round(@chaos_K * 100, 1) %>%
                </span>
              </div>
              <div class="h-bar">
                <div class={"h-bar-fill #{k_bar_class(@chaos_K)}"}
                     style={"width:#{min(100, @chaos_K * 100)}%;"}></div>
              </div>
              <div style="font-size:10px;color:var(--text-secondary);margin-top:4px;">
                <%= k_status_text(@chaos_K, @chaos_anomalous) %>
                &nbsp;·&nbsp; Window: <%= @chaos_windows %>/50 packets
              </div>
            </div>
          </div>

          <div class="card">
            <div class="card-title">Threat Level Gauge</div>
            <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px;">
              <%= for {name, color} <- [{"LOW","#4ade80"},{"MEDIUM","#fbbf24"},{"HIGH","#f97316"},{"CRITICAL","#f87171"}] do %>
                <div style={"text-align:center;flex:1;padding:6px 4px;border-radius:6px;border:2px solid #{if @threat_tier_name == name, do: color, else: "var(--border)"};background:#{if @threat_tier_name == name, do: "rgba(#{hex_to_rgb_str(color)},0.1)", else: "var(--bg-secondary)"};transition:all 0.3s;"}>
                  <div style={"font-size:10px;font-weight:700;color:#{if @threat_tier_name == name, do: color, else: "var(--text-secondary)"};"}>
                    <%= name %>
                  </div>
                  <div style={"width:8px;height:8px;border-radius:50%;margin:4px auto 0;background:#{if @threat_tier_name == name, do: color, else: "var(--border)"};#{if @threat_tier_name == name, do: "animation:pulse 1s infinite;", else: ""}"}></div>
                </div>
              <% end %>
            </div>
            <div style="font-size:11px;color:var(--text-secondary);">
              Tier transitions: <strong style="color:var(--text-primary);"><%= @threat_transitions %></strong>
              &nbsp;·&nbsp; Rule fires: <strong style="color:var(--text-primary);"><%= @rule_fires %></strong>
            </div>
          </div>

          <div class="card">
            <div class="card-title">Rule Engine Status</div>
            <div class="grid-2" style="gap:6px;">
              <%= for r <- ["RULE-01","RULE-02","RULE-03","RULE-04","RULE-05"] do %>
                <div style="display:flex;align-items:center;gap:6px;font-size:11px;">
                  <div style={"width:6px;height:6px;border-radius:50%;background:#{if @rule_fires > 0, do: "#fbbf24", else: "#374151"};"}>
                  </div>
                  <span class="mono" style="color:var(--text-secondary);"><%= r %></span>
                </div>
              <% end %>
            </div>
            <div style="margin-top:8px;font-size:11px;color:var(--text-secondary);">
              Total fires: <strong style="color:var(--text-primary);"><%= @rule_fires %></strong>
              &nbsp;·&nbsp; WORM triggers: <strong style={"color:#{if @worm_triggers > 0, do: "#f87171", else: "#4ade80"};"}>
                <%= @worm_triggers %>
              </strong>
            </div>
          </div>

          <div class="card">
            <div class="card-title">Demo Controls</div>
            <button class="btn btn-primary" phx-click="run_demo" phx-throttle="10000"
                    disabled={@demo_running} style="cursor:pointer;width:100%;justify-content:center;">
              <%= if @demo_running, do: "⏳ Running demo...", else: "▶ Run Demo Sequence" %>
            </button>
            <div style="font-size:10px;color:var(--text-secondary);margin-top:6px;">
              Escalates LOW→CRITICAL · triggers WORM · pushes chaos · dispatches agents
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # App: Defense Center
  # ---------------------------------------------------------------------------

  defp render_defense(assigns) do
    ~H"""
    <div class="anim-fade">
      <div class="section-header">
        🛡️ Defense Center — WORM · Firewall · Quarantine
        <span class="granite-badge">LOCAL AI</span>
      </div>
      <div class="grid-2">
        <div>
          <div class="card">
            <div class="card-title">WORM Lockdown</div>
            <div style="margin-bottom:10px;">
              <span class={if @worm_locked, do: "worm-locked", else: "worm-normal"}>
                <%= if @worm_locked, do: "🔒 LOCKED", else: "✓ NORMAL" %>
              </span>
            </div>
            <%= if @worm_reason != "" do %>
              <div class="mono" style="font-size:11px;color:#fca5a5;margin-bottom:6px;"><%= @worm_reason %></div>
            <% end %>
            <div class="stat-label">Activations: <%= @worm_lock_count %></div>
            <div class="stat-label">Rule triggers: <%= @worm_triggers %></div>
            <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">
              <button class="btn btn-ghost btn-sm" phx-click="worm_unlock" style="cursor:pointer;">
                🔓 Unlock
              </button>
              <button class="btn btn-ghost btn-sm" phx-click="toggle_worm_modal" style="cursor:pointer;">
                View Details
              </button>
            </div>
          </div>

          <div class="card">
            <div class="card-title">ClamAV Quarantine</div>
            <div class="stat-num" style={"color:#{if @quarantine_count > 0, do: "#f87171", else: "#4ade80"};"}>
              <%= @quarantine_count %>
            </div>
            <div class="stat-label">file(s) quarantined</div>
            <%= if @last_scan_result do %>
              <div class={"badge #{if @last_scan_result["quarantined"], do: "badge-red", else: "badge-green"}"} style="margin-top:6px;">
                Last scan: <%= @last_scan_result["status"] %>
              </div>
            <% end %>
          </div>

          <div class="card">
            <div class="card-title">Backup Repository — Veeam/IBM</div>
            <div style="margin-bottom:6px;">
              <span class={"badge #{if @veeam_lock_state == "UNLOCKED", do: "badge-green", else: "badge-red"}"}>
                <%= @veeam_lock_state %>
              </span>
              <span class="stat-label" style="margin-left:8px;"><%= @veeam_backup_count %> backup points</span>
            </div>
            <div class="stat-label">Integrity checks: <%= @veeam_integrity_checks %></div>
            <button class="btn btn-ghost btn-sm" phx-click="veeam_integrity_check" style="margin-top:8px;cursor:pointer;">
              Run Integrity Check
            </button>
          </div>
        </div>

        <div>
          <div class="card">
            <div class="card-title">Active Firewall Blocks (Step 16)</div>
            <%= if Enum.empty?(@active_firewall_blocks) do %>
              <div style="color:var(--text-secondary);font-size:12px;padding:16px 0;text-align:center;">
                No active blocks
              </div>
            <% else %>
              <div class="table-scroll">
                <table>
                  <thead><tr><th>IP</th><th>Expires</th></tr></thead>
                  <tbody>
                    <%= for blk <- @active_firewall_blocks do %>
                      <tr>
                        <td><span class="badge badge-red"><%= blk["ip"] %></span></td>
                        <td class="mono" style="font-size:10px;color:var(--text-secondary);">
                          <%= format_expiry(blk["expires_at_ms"]) %>
                        </td>
                      </tr>
                    <% end %>
                  </tbody>
                </table>
              </div>
            <% end %>
          </div>

          <div class="card">
            <div class="card-title">AI Triage — Local Inference</div>
            <form phx-submit="run_triage" style="display:flex;flex-direction:column;gap:8px;margin-bottom:10px;">
              <select name="event_type" class="input">
                <option value="entropy_anomaly">entropy_anomaly</option>
                <option value="auth_failure_spike">auth_failure_spike</option>
                <option value="lateral_movement_attempt">lateral_movement_attempt</option>
                <option value="credential_access">credential_access</option>
                <option value="rule_engine_test">rule_engine_test</option>
              </select>
              <div style="display:flex;gap:8px;align-items:center;">
                <label class="stat-label">Score (0–100):</label>
                <input name="score" type="number" min="0" max="100" value="50" class="input" style="width:80px;" />
              </div>
              <button type="submit" class="btn btn-primary btn-sm" style="cursor:pointer;">
                <span>⚡</span> Run local AI triage
              </button>
            </form>
            <%= cond do %>
              <% @last_triage == nil -> %>
                <div style="color:var(--text-secondary);font-size:11px;">No triage run yet.</div>
              <% @last_triage == :pending -> %>
                <div style="color:#fbbf24;font-size:11px;">⏳ Local AI triage in progress...</div>
              <% true -> %>
                <% tr = @last_triage %>
                <div class="anim-slide" style="font-size:11px;display:flex;flex-direction:column;gap:3px;">
                  <div style="display:flex;gap:8px;">
                    <span class="stat-label" style="min-width:110px;">Fast tier:</span>
                    <span class="badge badge-moe">⚡ MoE 3B</span>
                    <span class="badge badge-blue"><%= tr["fast_route"] %></span>
                  </div>
                  <%= if tr["heavy_severity"] do %>
                    <div style="display:flex;gap:8px;">
                      <span class="stat-label" style="min-width:110px;">Heavy tier:</span>
                      <span class="badge badge-dense">🧠 Dense 8B</span>
                      <span style="color:var(--text-primary)"><%= tr["heavy_severity"] %></span>
                    </div>
                    <div style="display:flex;gap:8px;">
                      <span class="stat-label" style="min-width:110px;">MITRE:</span>
                      <span class="mono" style="color:#60a5fa;"><%= tr["heavy_mitre"] %></span>
                    </div>
                  <% end %>
                  <div style="display:flex;gap:8px;margin-top:4px;">
                    <span class="stat-label" style="min-width:110px;">Final tier:</span>
                    <span class={"tier-badge tier-#{tier_int_to_name(tr["final_tier"])}"} style="font-size:10px;padding:2px 8px;">
                      <%= tier_int_to_name(tr["final_tier"]) %>
                    </span>
                    <%= if tr["rule_engine_overrode"] do %>
                      <span class="badge badge-red">Rule overrode model</span>
                    <% end %>
                  </div>
                  <div style="font-size:9px;color:#4b5563;margin-top:4px;">
                    Local AI classification is advisory — Rule Engine retains authority
                  </div>
                </div>
            <% end %>
          </div>

          <div class="card">
            <div class="card-title">Audit Chain</div>
            <div style="display:flex;gap:16px;">
              <div>
                <span class={"badge #{if @chain_valid, do: "badge-green", else: "badge-red"}"}>
                  <%= if @chain_valid, do: "✓ VALID", else: "✗ TAMPERED" %>
                </span>
                <div class="stat-label" style="margin-top:4px;">Entries: <strong style="color:var(--text-primary);"><%= @chain_length %></strong></div>
                <div class="mono" style="font-size:10px;color:var(--text-secondary);">Head: <%= @chain_head %>...</div>
              </div>
              <button class="btn btn-ghost btn-sm" phx-click="switch_app" phx-value-app="audit"
                      style="cursor:pointer;align-self:flex-start;">
                View Chain →
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end


  # ---------------------------------------------------------------------------
  # App: Agent Swarm
  # ---------------------------------------------------------------------------

  defp render_agents(assigns) do
    ~H"""
    <%
      fleet_total = length(@agent_statuses)
      running_count = Enum.count(@agent_statuses, &(&1["state"] == "RUNNING"))
      completed_count = Enum.count(@agent_statuses, &(&1["state"] == "COMPLETED"))
      heavy_count = Enum.count(@agent_statuses, &(&1["model"] == "heavy"))
      fast_count = max(fleet_total - heavy_count, 0)
      cat_counts = Enum.reduce(@agent_statuses, %{}, fn agent, acc ->
        Map.update(acc, agent["category"] || "unknown", 1, &(&1 + 1))
      end)
    %>

    <section class="agent-fleet anim-fade" aria-labelledby="agent-fleet-title" data-testid="agent-fleet">
      <header class="agent-fleet-hero">
        <div>
          <p class="agent-fleet-kicker">Autonomous assurance workforce</p>
          <h1 class="agent-fleet-title" id="agent-fleet-title">Agent Fleet</h1>
          <p class="agent-fleet-subtitle">
            <%= fleet_total %> security agents are synchronized from the native bridge. Each task stays inside the Astartis Zero Trust workflow and is recorded in the audit chain.
          </p>
        </div>
        <div class="agent-fleet-posture" aria-label="Agent fleet inference profile">
          <span class="agent-fleet-posture-marker"></span>
          <div>
            <small>Inference profile</small>
            <strong><%= fast_count %> fast routes / <%= heavy_count %> deep review</strong>
          </div>
        </div>
      </header>

      <div class="agent-fleet-metrics" aria-label="Agent fleet summary">
        <article class="agent-fleet-metric agent-fleet-metric--active">
          <span class="agent-fleet-metric-label">Fleet inventory</span>
          <strong class="agent-fleet-metric-value"><%= fleet_total %></strong>
          <span class="agent-fleet-metric-note"><%= if fleet_total == 77, do: "65 personas + 12 ECC agents", else: "profiles loaded from the bridge" %></span>
        </article>
        <article class="agent-fleet-metric agent-fleet-metric--running">
          <span class="agent-fleet-metric-label">In progress</span>
          <strong class="agent-fleet-metric-value"><%= running_count %></strong>
          <span class="agent-fleet-metric-note"><%= if running_count > 0, do: "tasks currently being evaluated", else: "no tasks currently running" %></span>
        </article>
        <article class="agent-fleet-metric agent-fleet-metric--completed">
          <span class="agent-fleet-metric-label">Completed</span>
          <strong class="agent-fleet-metric-value"><%= completed_count %></strong>
          <span class="agent-fleet-metric-note">completed task executions</span>
        </article>
        <article class="agent-fleet-metric agent-fleet-metric--queue">
          <span class="agent-fleet-metric-label">Queue depth</span>
          <strong class="agent-fleet-metric-value"><%= @agent_queue_depth %></strong>
          <span class="agent-fleet-metric-note"><%= if @agent_queue_depth > 0, do: "waiting for an available specialist", else: "ready for the next task" %></span>
        </article>
      </div>

      <div class="agent-fleet-workspace">
        <section class="agent-panel" aria-labelledby="agent-directory-title">
          <div class="agent-panel-header">
            <div>
              <h2 class="agent-panel-title" id="agent-directory-title">Live agent directory</h2>
              <p class="agent-panel-description">Runtime status, model route, specialization, and task history for every active agent.</p>
            </div>
            <span class="agent-panel-count"><%= fleet_total %> LOADED</span>
          </div>

          <div class="agent-grid" role="list" aria-label="Astartis agent statuses">
            <%= if Enum.empty?(@agent_statuses) do %>
              <div class="agent-empty">The native bridge is still loading the agent catalog.</div>
            <% else %>
              <%= for agent <- Enum.sort_by(@agent_statuses, &(&1["name"] || "")) do %>
                <%
                  state = agent["state"] || "IDLE"
                  state_class = String.downcase(state)
                  agent_name = agent["name"] || "unnamed_agent"
                  category = agent["category"] || "general"
                  heavy? = agent["model"] == "heavy"
                %>
                <article class={"agent-node agent-node--#{state_class}"} role="listitem" title={agent_description(agent_name)}>
                  <div class="agent-node-header">
                    <span class="agent-name"><%= agent_name %></span>
                    <span class={"agent-state agent-state--#{state_class}"}>
                      <span class={"agent-state-dot dot-#{state_class}"}></span>
                      <%= String.capitalize(state_class) %>
                    </span>
                  </div>
                  <p class="agent-node-description"><%= agent_description(agent_name) %></p>
                  <div class="agent-node-meta">
                    <span class="agent-category"><%= String.replace(category, "_", " ") %></span>
                    <span class={"agent-model #{if heavy?, do: "agent-model--heavy", else: ""}"}>
                      <%= if heavy?, do: "DENSE 8B", else: "MOE 3B" %>
                    </span>
                  </div>
                  <div class="agent-work-counts" aria-label="Agent task counts">
                    <span><strong><%= agent["tasks_completed"] || 0 %></strong> complete</span>
                    <span class="agent-fail-count"><%= agent["tasks_failed"] || 0 %> failed</span>
                  </div>
                </article>
              <% end %>
            <% end %>
          </div>
        </section>

        <aside>
          <section class="agent-panel" aria-labelledby="agent-submit-title">
            <div class="agent-panel-header">
              <div>
                <h2 class="agent-panel-title" id="agent-submit-title">Route a task</h2>
                <p class="agent-panel-description">Choose a specialist and submit a scoped security task to the local AI runtime.</p>
              </div>
            </div>
            <form phx-submit="agent_submit_task" class="agent-composer">
              <label class="agent-form-label" for="agent-task-target">Specialist</label>
              <select id="agent-task-target" name="agent" class="input">
                <option value="alert_triage">alert_triage &middot; MoE 3B &middot; SOC</option>
                <option value="recon_agent">recon_agent &middot; MoE 3B &middot; pen test</option>
                <option value="security_reviewer">security_reviewer &middot; Dense 8B &middot; SE team</option>
                <option value="threat_hunter">threat_hunter &middot; Dense 8B &middot; SOC</option>
                <option value="vuln_scanner">vuln_scanner &middot; MoE 3B &middot; pen test</option>
                <option value="incident_responder">incident_responder &middot; Dense 8B &middot; SOC</option>
                <option value="code_reviewer">code_reviewer &middot; MoE 3B &middot; SE team</option>
                <option value="bug_hunter">bug_hunter &middot; Dense 8B &middot; SE team</option>
                <option value="siem_analyst">siem_analyst &middot; MoE 3B &middot; SOC</option>
                <option value="report_generator">report_generator &middot; Dense 8B &middot; pen test</option>
              </select>
              <label class="agent-form-label" for="agent-task-input">Task input</label>
              <input id="agent-task-input" name="input" type="text" class="input"
                     placeholder="Alert text, code snippet, or scan result" />
              <button type="submit" class="btn btn-primary agent-submit">Submit to local AI</button>
            </form>

            <%= if @last_agent_task_id do %>
              <%
                has_result? = @last_agent_result && @last_agent_result != :pending
                result_ok? = has_result? && @last_agent_result["ok"]
                result_model = if has_result?, do: agent_model_label(@last_agent_result["model_used"]), else: nil
              %>
              <div class={"agent-task-feedback anim-slide #{if has_result? && !result_ok?, do: "agent-task-feedback--error", else: ""}"} aria-live="polite">
                <div class="agent-task-feedback__label">TASK</div>
                <div class="agent-task-feedback__id"><%= @last_agent_task_id %></div>
                <%= if has_result? do %>
                  <div class="agent-task-feedback__result">
                    <strong><%= if result_ok?, do: "Completed", else: "Failed" %></strong>
                    <span> &middot; <%= result_model %></span>
                  </div>
                <% else %>
                  <div class="agent-task-feedback__pending">Local AI is evaluating the task.</div>
                <% end %>
              </div>
            <% end %>
          </section>

          <section class="agent-panel" aria-labelledby="agent-distribution-title">
            <div class="agent-panel-header">
              <div>
                <h2 class="agent-panel-title" id="agent-distribution-title">Specialization mix</h2>
                <p class="agent-panel-description">How the current fleet is distributed across security disciplines.</p>
              </div>
            </div>
            <div class="agent-distribution">
              <%= for {category, label, tone} <- [{"pen_test", "Penetration testing", "pentest"}, {"se_team", "Security engineering", "se"}, {"soc", "Security operations", "soc"}] do %>
                <% category_count = Map.get(cat_counts, category, 0) %>
                <div class="agent-distribution-row">
                  <strong class="agent-distribution-count"><%= category_count %></strong>
                  <div>
                    <div class="agent-distribution-label">
                      <span><%= label %></span>
                      <span><%= trunc(category_count / max(1, fleet_total) * 100) %>%</span>
                    </div>
                    <div class="agent-distribution-bar" aria-hidden="true">
                      <div class={"agent-distribution-fill agent-distribution-fill--#{tone}"} style={"width:#{trunc(category_count / max(1, fleet_total) * 100)}%"}></div>
                    </div>
                  </div>
                </div>
              <% end %>
            </div>
          </section>
        </aside>
      </div>
    </section>
    """
  end

  # ---------------------------------------------------------------------------
  # App: Sandbox File Manager
  # ---------------------------------------------------------------------------

  defp render_sandbox(assigns) do
    ~H"""
    <div class="anim-fade">
      <div class="section-header">
        📁 Sandbox File Manager — Poisoned Decoy Environment
        <div style="display:flex;gap:8px;">
          <button class="btn btn-ghost btn-sm" phx-click="plant_decoy" style="cursor:pointer;">
            🎣 Plant Decoy
          </button>
          <button class="btn btn-ghost btn-sm" style="cursor:pointer;">
            + New File
          </button>
        </div>
      </div>
      <div class="grid-2">
        <%!-- File tree --%>
        <div class="card" style="min-height:400px;">
          <div class="card-title">
            📁 sandbox/
            <span class="mono" style="font-size:9px;color:#4b5563;"><%= @sandbox_root %></span>
          </div>
          <div class="file-tree">
            <%= if Enum.empty?(@sandbox_entries) do %>
              <div style="color:var(--text-secondary);font-size:12px;padding:16px 0;text-align:center;">
                No sandbox entries — bridge connecting...
              </div>
            <% else %>
              <%= for entry <- Enum.sort_by(@sandbox_entries, &(&1["rel_path"])) do %>
                <div class={"file-item #{if entry["locked"], do: "locked", else: ""} #{if is_poisoned?(entry), do: "poisoned", else: ""} #{if @sandbox_selected && @sandbox_selected["rel_path"] == entry["rel_path"], do: "selected", else: ""}"}
                     phx-click="sandbox_select" phx-value-path={entry["rel_path"]}>
                  <span style="font-size:14px;"><%= file_icon(entry) %></span>
                  <span class="mono" style={"font-size:11px;color:#{entry_color(entry)};flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"}>
                    <%= entry["rel_path"] %>
                  </span>
                  <%= if is_poisoned?(entry) do %>
                    <span class="badge badge-yellow" style="font-size:8px;padding:1px 4px;">DECOY</span>
                  <% end %>
                  <%= if entry["locked"] do %>
                    <span style="font-size:11px;">🔒</span>
                  <% end %>
                  <span style="font-size:10px;color:var(--text-secondary);"><%= format_bytes(entry["size_bytes"] || 0) %></span>
                </div>
              <% end %>
            <% end %>
          </div>
          <div style="margin-top:12px;padding-top:8px;border-top:1px solid var(--border);display:flex;gap:6px;">
            <span class="stat-label">Total: <%= length(@sandbox_entries) %> entries</span>
            <span class="stat-label">·</span>
            <span class="stat-label" style={"color:#{if @decoy_events > 0, do: "#fbbf24", else: "var(--text-secondary)"};"}>
              <%= @decoy_events %> decoy triggers
            </span>
          </div>
        </div>

        <%!-- Preview panel --%>
        <div>
          <%= if @sandbox_selected do %>
            <div class="card anim-slide">
              <div class="card-title">Preview: <%= @sandbox_selected["rel_path"] %></div>
              <div style="display:flex;flex-direction:column;gap:6px;">
                <div style="display:flex;gap:8px;">
                  <span class="stat-label" style="min-width:80px;">Type:</span>
                  <span style="font-size:12px;"><%= @sandbox_selected["type"] %></span>
                </div>
                <div style="display:flex;gap:8px;">
                  <span class="stat-label" style="min-width:80px;">Size:</span>
                  <span style="font-size:12px;"><%= format_bytes(@sandbox_selected["size_bytes"] || 0) %></span>
                </div>
                <div style="display:flex;gap:8px;">
                  <span class="stat-label" style="min-width:80px;">Version:</span>
                  <span style="font-size:12px;">v<%= @sandbox_selected["version"] || 1 %></span>
                </div>
                <div style="display:flex;gap:8px;">
                  <span class="stat-label" style="min-width:80px;">Locked:</span>
                  <span class={"badge #{if @sandbox_selected["locked"], do: "badge-red", else: "badge-green"}"}>
                    <%= if @sandbox_selected["locked"], do: "🔒 Yes", else: "✓ No" %>
                  </span>
                </div>
                <%= if is_poisoned?(@sandbox_selected) do %>
                  <div style="padding:8px;background:rgba(245,158,11,0.1);border:1px solid var(--warning);border-radius:6px;margin-top:6px;">
                    <div style="font-size:11px;color:var(--warning);font-weight:700;">⚠ POISONED DECOY ASSET</div>
                    <div style="font-size:10px;color:var(--text-secondary);margin-top:2px;">
                      This file is a honey-trap. Any access will trigger an alert.
                    </div>
                  </div>
                <% end %>
                <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">
                  <button class="btn btn-ghost btn-sm" phx-click="sandbox_lock"
                          phx-value-path={@sandbox_selected["rel_path"]} style="cursor:pointer;">
                    🔒 Lock File
                  </button>
                  <button class="btn btn-ghost btn-sm" style="cursor:pointer;">
                    📋 Copy Path
                  </button>
                  <button class="btn btn-ghost btn-sm" style="cursor:pointer;">
                    🔍 Forensic Log
                  </button>
                </div>
              </div>
            </div>
          <% else %>
            <div class="card" style="min-height:200px;display:flex;align-items:center;justify-content:center;">
              <div style="text-align:center;color:var(--text-secondary);">
                <div style="font-size:32px;margin-bottom:8px;">📄</div>
                <div style="font-size:12px;">Click a file to preview</div>
              </div>
            </div>
          <% end %>

          <div class="card" style="margin-top:12px;">
            <div class="card-title">Decoy Status</div>
            <div style="display:flex;gap:16px;">
              <div>
                <div class="stat-num" style={"color:#{if @decoy_events > 0, do: "#fbbf24", else: "#4ade80"};"}>
                  <%= @decoy_events %>
                </div>
                <div class="stat-label">Decoy trigger events</div>
              </div>
              <div>
                <div class="stat-num"><%= length(@sandbox_entries) %></div>
                <div class="stat-label">Sandbox entries</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end


  # ---------------------------------------------------------------------------
  # App: Threat Reports (MITRE + D3FEND + frameworks)
  # ---------------------------------------------------------------------------

  defp render_reports(assigns) do
    ~H"""
    <div class="anim-fade">
      <div class="section-header">
        📊 Threat Report — Attribution · MITRE · Kill Chain
        <span class="granite-badge">LOCAL AI</span>
      </div>
      <div class="card">
        <div class="tabs">
          <%= for {id, label} <- [{"attack","MITRE ATT&CK"},{"defend","MITRE D3FEND"},{"zta","NIST ZTA"},{"csf","NIST CSF 2.0"},{"killchain","Kill Chain"}] do %>
            <button class={"tab-btn #{if @active_tab == id, do: "active", else: ""}"}
                    phx-click="switch_tab" phx-value-tab={id} style="cursor:pointer;">
              <%= label %>
            </button>
          <% end %>
        </div>

        <%= if @active_tab == "attack" do %>
          <div class="card-title">MITRE ATT&CK — Observed Techniques</div>
          <%= if Enum.empty?(@attribution_techniques) do %>
            <div style="color:var(--text-secondary);font-size:12px;padding:24px;text-align:center;">
              No techniques yet — run the demo to populate ATT&CK mapping
            </div>
          <% else %>
            <div class="table-scroll">
              <table>
                <thead><tr><th>Technique ID</th><th>Name</th><th>Tactic</th><th>Evidence</th></tr></thead>
                <tbody>
                  <%= for t <- @attribution_techniques do %>
                    <tr>
                      <td class="technique-id"><%= t["technique_id"] %></td>
                      <td style="font-size:12px;"><%= t["name"] %></td>
                      <td><span class="tactic-tag"><%= t["tactic"] %></span></td>
                      <td class="mono" style="font-size:10px;color:var(--text-secondary);"><%= t["evidence"] %></td>
                    </tr>
                  <% end %>
                </tbody>
              </table>
            </div>
          <% end %>
        <% end %>

        <%= if @active_tab == "defend" do %>
          <div class="card-title">MITRE D3FEND — Defensive Technique Mapping</div>
          <%= for {src, id, desc} <- d3fend_mappings() do %>
            <div class="fw-row">
              <span class="fw-id"><%= id %></span>
              <span class="fw-desc"><%= desc %></span>
              <span class="fw-src"><%= src %></span>
            </div>
          <% end %>
        <% end %>

        <%= if @active_tab == "zta" do %>
          <div class="card-title">NIST SP 800-207 — Zero Trust Architecture Pillars</div>
          <%= for {pillar, desc, module} <- nist_zta_mappings() do %>
            <div class="fw-row">
              <span class="fw-id"><%= pillar %></span>
              <span class="fw-desc"><%= desc %></span>
              <span class="fw-src"><%= module %></span>
            </div>
          <% end %>
        <% end %>

        <%= if @active_tab == "csf" do %>
          <div class="card-title">NIST CSF 2.0 — Core Functions</div>
          <div class="csf-grid">
            <%= for {fn_id, fn_class, items} <- csf_mappings() do %>
              <div class="csf-col">
                <div class={"csf-title #{fn_class}"}><%= fn_id %></div>
                <%= for item <- items do %>
                  <div class="csf-item"><%= item %></div>
                <% end %>
              </div>
            <% end %>
          </div>
        <% end %>

        <%= if @active_tab == "killchain" do %>
          <div class="card-title">Lockheed Martin Cyber Kill Chain — Interception Points</div>
          <div class="kc-grid" style="margin-bottom:16px;">
            <%= for {num, stage, intercepted, _detail} <- kill_chain_stages() do %>
              <div class={"kc-stage #{if intercepted, do: "kc-intercepted", else: ""}"}>
                <div style="font-size:9px;color:#4b5563;margin-bottom:2px;">Stage <%= num %></div>
                <div class="kc-stage-name"><%= stage %></div>
                <span class={"kc-badge #{if intercepted, do: "kc-badge-int", else: "kc-badge-pass"}"}>
                  <%= if intercepted, do: "Intercepted", else: "Pass" %>
                </span>
              </div>
            <% end %>
          </div>
          <div>
            <%= for {_n, stage, true, detail} <- kill_chain_stages() do %>
              <div class="fw-row">
                <span class="fw-id" style="color:#4ade80;"><%= stage %></span>
                <span class="fw-desc"><%= detail %></span>
              </div>
            <% end %>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # App: Audit Chain
  # ---------------------------------------------------------------------------

  defp render_audit(assigns) do
    ~H"""
    <div class="anim-fade">
      <div class="section-header">
        📜 Audit Chain — Immutable SHA-256 Signed
        <div style="display:flex;gap:8px;align-items:center;">
          <span class={"badge #{if @chain_valid, do: "badge-green", else: "badge-red"}"}>
            <%= if @chain_valid, do: "✓ CHAIN VALID", else: "✗ TAMPERED" %>
          </span>
          <span class="granite-badge">LOCAL AI</span>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Block Chain Visualization — <%= @chain_length %> entries</div>
        <div class="chain-blocks">
          <%= for {block, i} <- Enum.with_index(build_demo_audit_blocks(@chain_length, @chain_head)) do %>
            <div class={"chain-block #{if @audit_selected == i, do: "selected", else: ""}"}
                 phx-click="audit_select" phx-value-idx={i}>
              <div style="font-size:9px;color:#4b5563;margin-bottom:2px;">#<%= block.index %></div>
              <div class="chain-event"><%= block.event %></div>
              <div class="chain-hash"><%= String.slice(block.hash, 0, 12) %>...</div>
            </div>
            <div class="chain-arrow">→</div>
          <% end %>
          <%= if @chain_length == 0 do %>
            <div style="color:var(--text-secondary);font-size:12px;padding:20px;">
              No audit entries yet — run the demo to generate events
            </div>
          <% end %>
        </div>
      </div>

      <div class="grid-2" style="margin-top:12px;">
        <div class="card">
          <div class="card-title">Chain Statistics</div>
          <div class="grid-2" style="gap:8px;">
            <div>
              <div class="stat-num"><%= @chain_length %></div>
              <div class="stat-label">Total entries</div>
            </div>
            <div>
              <div class="stat-num" style={"color:#{if @chain_valid, do: "#4ade80", else: "#f87171"};"}>
                <%= if @chain_valid, do: "VALID", else: "TAMPERED" %>
              </div>
              <div class="stat-label">Chain integrity</div>
            </div>
          </div>
          <div class="mono" style="font-size:10px;color:var(--text-secondary);margin-top:8px;">
            Head hash: <%= @chain_head %>...
          </div>
        </div>

        <div class="card">
          <div class="card-title">Tamper Detection Demo</div>
          <p style="font-size:12px;color:var(--text-secondary);margin-bottom:10px;">
            The audit chain uses SHA-256 hash chaining. Each block includes the previous hash — any modification breaks the chain.
          </p>
          <div style="padding:8px;background:rgba(16,185,129,0.08);border:1px solid var(--success);border-radius:6px;">
            <div style="font-size:11px;color:var(--success);">
              ✓ Chain integrity: all hashes verified by C++ backend
            </div>
            <div style="font-size:10px;color:var(--text-secondary);margin-top:4px;">
              ECDSA(secp256k1) signatures applied on every entry
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # App: Settings
  # ---------------------------------------------------------------------------

  defp render_settings(assigns) do
    ~H"""
    <%
      {capture_label, capture_tone} = telemetry_status(assigns)
      {evidence_label, evidence_tone} = evidence_status(assigns)
      running_agents = Enum.count(@agent_statuses, &(&1["state"] == "RUNNING"))
      capture_adapter = if @packet_capture_adapter == "", do: "No adapter confirmed", else: @packet_capture_adapter
      bridge_status = cond do
        @bridge_elevated == true -> "ELEVATED"
        @bridge_elevated == false -> "STANDARD PROCESS"
        true -> "NOT YET REPORTED"
      end
    %>
    <section class="terminal-workspace runtime-settings anim-fade" aria-labelledby="runtime-settings-title" data-testid="runtime-settings">
      <header class="terminal-workspace-hero">
        <div>
          <p class="terminal-workspace-kicker">Astartis &times; Codex</p>
          <h1 class="terminal-workspace-title" id="runtime-settings-title">Runtime &amp; Workspace Configuration</h1>
          <p class="terminal-workspace-subtitle">Review the live local runtime and tune presentation preferences for this browser session. Protection controls and evidence retention remain managed by Astartis.</p>
        </div>
        <div class="terminal-dock-status" aria-label="Runtime evidence status">
          <span class={"terminal-state-chip terminal-state-chip--#{capture_tone}"}>Telemetry: <%= capture_label %></span>
          <span class={"terminal-state-chip terminal-state-chip--#{evidence_tone}"}>Evidence: <%= evidence_label %></span>
        </div>
      </header>

      <div class="runtime-settings-grid">
        <div>
          <section class="runtime-settings-panel" aria-labelledby="runtime-evidence-title">
            <div class="runtime-settings-panel-head">
              <div>
                <h2 class="runtime-settings-panel-title" id="runtime-evidence-title">Live runtime evidence</h2>
                <p class="runtime-settings-panel-description">Values below are read from the current bridge snapshot and LiveView session.</p>
              </div>
              <span class="runtime-settings-readonly">Read-only</span>
            </div>
            <div class="runtime-list">
              <div class="runtime-row">
                <div>
                  <div class="runtime-row-label">Npcap sensor</div>
                  <div class="runtime-row-note"><%= @packet_windows %> entropy windows observed; mode comes from the current bridge snapshot.</div>
                </div>
                <div class="runtime-row-value"><%= capture_label %> / <%= @packet_capture_mode %></div>
              </div>
              <div class="runtime-row">
                <div>
                  <div class="runtime-row-label">Capture adapter</div>
                  <div class="runtime-row-note">The active adapter is reported only after a capture session is confirmed.</div>
                </div>
                <div class="runtime-row-value"><%= capture_adapter %></div>
              </div>
              <div class="runtime-row">
                <div>
                  <div class="runtime-row-label">Bridge privilege</div>
                  <div class="runtime-row-note">Elevation is decided when the local bridge starts; this page cannot raise or lower it.</div>
                </div>
                <div class="runtime-row-value"><%= bridge_status %></div>
              </div>
              <div class="runtime-row">
                <div>
                  <div class="runtime-row-label">Agent fleet</div>
                  <div class="runtime-row-note">Loaded and running counts are current bridge-reported agent status.</div>
                </div>
                <div class="runtime-row-value"><%= length(@agent_statuses) %> loaded / <%= running_agents %> running / queue <%= @agent_queue_depth %></div>
              </div>
              <div class="runtime-row">
                <div>
                  <div class="runtime-row-label">WORM and audit evidence</div>
                  <div class="runtime-row-note">WORM state and the hash-chain verification result are controlled by Astartis.</div>
                </div>
                <div class="runtime-row-value"><%= if @worm_locked, do: "WORM LOCKED", else: "WORM NORMAL" %> / <%= if @chain_valid, do: "#{@chain_length} VERIFIED ENTRIES", else: "#{@chain_length} ENTRIES - REVIEW" %></div>
              </div>
            </div>
          </section>

          <section class="runtime-settings-panel" aria-labelledby="runtime-guardrails-title">
            <div class="runtime-settings-panel-head">
              <div>
                <h2 class="runtime-settings-panel-title" id="runtime-guardrails-title">Backend-managed controls</h2>
                <p class="runtime-settings-panel-description">Shown for clarity, not editable from this workspace.</p>
              </div>
              <span class="runtime-settings-readonly">Astartis-managed</span>
            </div>
            <div class="runtime-list">
              <div class="runtime-row">
                <div>
                  <div class="runtime-row-label">Bridge launch and elevation</div>
                  <div class="runtime-row-note">Configured at bridge startup, outside this LiveView session.</div>
                </div>
                <div class="runtime-row-value"><%= bridge_status %></div>
              </div>
              <div class="runtime-row">
                <div>
                  <div class="runtime-row-label">Evidence retention and WORM recovery</div>
                  <div class="runtime-row-note">Audit retention and recovery approvals remain enforced by the native protection workflow.</div>
                </div>
                <div class="runtime-row-value"><%= if @chain_valid, do: "VERIFIED", else: "VERIFY" %></div>
              </div>
            </div>
          </section>
        </div>

        <aside>
          <section class="runtime-settings-panel" aria-labelledby="workspace-preferences-title">
            <div class="runtime-settings-panel-head">
              <div>
                <h2 class="runtime-settings-panel-title" id="workspace-preferences-title">Session presentation</h2>
                <p class="runtime-settings-panel-description">These preferences apply immediately to this LiveView session only.</p>
              </div>
            </div>
            <div class="runtime-config-form">
              <form class="runtime-config-field" phx-change="set_dashboard_density">
                <label class="runtime-config-label" for="dashboard-density">Dashboard density</label>
                <select id="dashboard-density" class="runtime-config-select" name="density">
                  <option value="comfortable" selected={@dashboard_density == "comfortable"}>Comfortable</option>
                  <option value="compact" selected={@dashboard_density == "compact"}>Compact</option>
                </select>
                <span class="runtime-config-help">Changes card spacing and workspace density immediately. It is not stored outside this browser session.</span>
              </form>

              <form class="runtime-config-field" phx-change="set_evidence_window">
                <label class="runtime-config-label" for="evidence-window">Evidence view label</label>
                <select id="evidence-window" class="runtime-config-select" name="window">
                  <option value="Current session" selected={@evidence_window_label == "Current session"}>Current session</option>
                  <option value="Last 24 hours" selected={@evidence_window_label == "Last 24 hours"}>Last 24 hours</option>
                  <option value="Last 7 days" selected={@evidence_window_label == "Last 7 days"}>Last 7 days</option>
                </select>
                <span class="runtime-config-help">Changes the evidence window label in the workspace. It does not alter audit retention or query historical records.</span>
              </form>

              <form class="runtime-config-field" phx-change="set_terminal_dock_visibility">
                <label class="runtime-config-label" for="terminal-dock-visibility">Terminal dock</label>
                <select id="terminal-dock-visibility" class="runtime-config-select" name="visibility">
                  <option value="visible" selected={@terminal_dock_visible}>Visible</option>
                  <option value="hidden" selected={not @terminal_dock_visible}>Hidden</option>
                </select>
                <span class="runtime-config-help">Shows or hides the compact dock. The Terminal workspace remains available from navigation.</span>
              </form>
            </div>
          </section>

          <section class="runtime-settings-panel" aria-labelledby="capture-routing-title">
            <div class="runtime-settings-panel-head">
              <div>
                <h2 class="runtime-settings-panel-title" id="capture-routing-title">Capture routing</h2>
                <p class="runtime-settings-panel-description">Choose which discovered adapter Astartis should use on the next capture start.</p>
              </div>
            </div>
            <div class="runtime-config-form">
              <%= if @capture_adapters != [] do %>
                <form class="runtime-config-field" phx-change="packet_capture_adapter_select">
                  <label class="runtime-config-label" for="runtime-capture-adapter">Capture adapter</label>
                  <select id="runtime-capture-adapter" class="runtime-config-select" name="adapter"
                          disabled={@packet_capture_running or @capture_action_state in ["starting", "stopping"]}>
                    <option value="">Automatic selection</option>
                    <%= for adapter <- @capture_adapters, adapter["up"] and not adapter["loopback"] do %>
                      <option value={adapter["name"]} selected={@capture_adapter_choice == adapter["name"]}>
                        <%= if adapter["description"] in [nil, ""], do: adapter["name"], else: adapter["description"] %>
                      </option>
                    <% end %>
                  </select>
                  <span class="runtime-config-help"><%= if @packet_capture_running, do: "Capture is active, so routing is locked until it stops.", else: "The selected adapter is passed to the bridge when you start capture." %></span>
                </form>
              <% else %>
                <div class="runtime-settings-note">No adapters have been reported yet. Astartis requests the adapter list from the local bridge when the dashboard connects.</div>
              <% end %>

              <div class="runtime-settings-note">
                Capture mode is currently <strong><%= @packet_capture_mode %></strong>. Live Npcap and simulation states are labelled separately; the mode itself is bridge-managed.
              </div>
              <%= if @capture_error do %>
                <div class="runtime-settings-note" style="border-left-color:#da1e28;background:#fff1f1;"><%= @capture_error %></div>
              <% end %>
            </div>
          </section>
        </aside>
      </div>
    </section>
    """
  end

  # ---------------------------------------------------------------------------
  # Stage detail panel (used inside Pipeline app)
  # ---------------------------------------------------------------------------

  defp render_stage_detail(%{pipeline_stage: "packet"} = assigns) do
    ~H"""
    <div class="grid-4" style="gap:8px;">
      <div><div class="stat-label">Chaos windows</div><div style="font-size:16px;font-weight:700;"><%= @chaos_windows %></div></div>
      <div><div class="stat-label">Chain entries</div><div style="font-size:16px;font-weight:700;"><%= @chain_length %></div></div>
      <div><div class="stat-label">Rule fires</div><div style={"font-size:16px;font-weight:700;color:#{if @rule_fires > 0, do: "#fbbf24", else: "#4ade80"};"}><%= @rule_fires %></div></div>
      <div><div class="stat-label">WORM triggers</div><div style={"font-size:16px;font-weight:700;color:#{if @worm_triggers > 0, do: "#f87171", else: "#4ade80"};"}><%= @worm_triggers %></div></div>
    </div>
    """
  end
  defp render_stage_detail(%{pipeline_stage: "entropy"} = assigns) do
    ~H"""
    <div style="display:flex;gap:16px;align-items:flex-start;">
      <div>
        <div class="stat-label">K score</div>
        <div style={"font-size:20px;font-weight:700;color:#{if @chaos_K > 0.7, do: "#f87171", else: "#4ade80"};"}>
          <%= :erlang.float_to_binary(@chaos_K + 0.0, [{:decimals, 4}]) %>
        </div>
        <span class={"badge #{if @chaos_anomalous, do: "badge-red", else: "badge-green"}"}>
          <%= if @chaos_anomalous, do: "ANOMALOUS", else: "NORMAL" %>
        </span>
      </div>
      <div style="flex:1;">
        <%= Phoenix.HTML.raw(chaos_svg_string(@chaos_history)) %>
      </div>
    </div>
    """
  end
  defp render_stage_detail(%{pipeline_stage: "triage"} = assigns) do
    ~H"""
    <%= cond do %>
      <% @last_triage == nil -> %>
        <div style="color:var(--text-secondary);font-size:12px;">No triage run yet.</div>
      <% @last_triage == :pending -> %>
        <div style="color:#fbbf24;">⏳ Local AI processing...</div>
      <% true -> %>
        <% tr = @last_triage %>
        <div class="grid-4" style="gap:8px;">
          <div><div class="stat-label">Event type</div><div class="mono" style="color:#60a5fa;font-size:12px;"><%= tr["event_type"] %></div></div>
          <div><div class="stat-label">Fast route</div><div><span class={"badge #{if tr["fast_route"] == "escalate", do: "badge-red", else: "badge-green"}"}><%= tr["fast_route"] %></span></div></div>
          <div><div class="stat-label">Model</div><div><span class="badge badge-moe">⚡ MoE 3B</span></div></div>
          <div><div class="stat-label">Final tier</div><div><span class={"tier-badge tier-#{tier_int_to_name(tr["final_tier"])}"} style="font-size:10px;padding:2px 8px;"><%= tier_int_to_name(tr["final_tier"]) %></span></div></div>
        </div>
    <% end %>
    """
  end
  defp render_stage_detail(%{pipeline_stage: _stage} = assigns) do
    ~H"""
    <div class="grid-4" style="gap:8px;">
      <div><div class="stat-label">Stage</div><div class="mono" style="font-size:12px;color:var(--ibm-granite);"><%= @pipeline_stage %></div></div>
      <div><div class="stat-label">Threat tier</div><div><span class={"tier-badge tier-#{@threat_tier_name}"} style="font-size:10px;padding:2px 8px;"><%= @threat_tier_name %></span></div></div>
      <div><div class="stat-label">WORM</div><div><span class={if @worm_locked, do: "worm-locked", else: "worm-normal"} style="font-size:11px;padding:3px 8px;"><%= if @worm_locked, do: "LOCKED", else: "OK" %></span></div></div>
      <div><div class="stat-label">Chain</div><div style="font-size:16px;font-weight:700;"><%= @chain_length %></div></div>
    </div>
    """
  end


  # ---------------------------------------------------------------------------
  # App: Pipeline Forge
  # ---------------------------------------------------------------------------

  defp render_pipeline(assigns) do
    ~H"""
    <div class="anim-fade">
      <div class="section-header">
        🔧 Live System Pipeline — OMIDAX + DIBANET
        <span class="granite-badge">LOCAL AI</span>
      </div>

      <div class="card">
        <div style="font-size:10px;color:var(--text-secondary);margin-bottom:10px;">
          Click any stage for detail &nbsp;·&nbsp; Active stages glow green/red
        </div>
        <div class="pipeline-strip">
          <%!-- OMIDAX group label --%>
          <div style="flex-shrink:0;writing-mode:vertical-rl;transform:rotate(180deg);font-size:9px;text-transform:uppercase;letter-spacing:0.1em;color:#60a5fa;margin-right:8px;align-self:center;">
            OMIDAX
          </div>

          <%= for {stage, step, name, signal} <- pipeline_stages_omidax() do %>
            <% lv = stage_level(stage, assigns) %>
            <div class={"pipe-node #{pipe_level_class(lv)} #{if @pipeline_stage == stage, do: "pipe-node-selected", else: ""}"}
                 phx-click="select_pipeline_stage" phx-value-stage={stage}>
              <div style="font-size:8px;color:#4b5563;margin-bottom:2px;"><%= step %></div>
              <div style="font-size:10px;font-weight:700;color:var(--text-secondary);line-height:1.2;margin-bottom:2px;"><%= name %></div>
              <div style="font-size:9px;color:#374151;"><%= signal %></div>
              <div class={"pipe-dot #{pipe_dot_class(lv)}"}></div>
            </div>
            <div class="pipe-connector">→</div>
          <% end %>

          <%!-- Divider --%>
          <div style="flex-shrink:0;display:flex;flex-direction:column;align-items:center;justify-content:center;margin:0 8px;gap:3px;">
            <div style="width:1px;height:28px;background:var(--border);"></div>
            <div style="font-size:8px;text-transform:uppercase;letter-spacing:0.08em;color:#a78bfa;writing-mode:vertical-rl;transform:rotate(180deg);">DIBANET</div>
            <div style="width:1px;height:28px;background:var(--border);"></div>
          </div>

          <%= for {stage, step, name, signal} <- pipeline_stages_dibanet() do %>
            <% lv = stage_level(stage, assigns) %>
            <div class={"pipe-node #{pipe_level_class(lv)} #{if @pipeline_stage == stage, do: "pipe-node-selected", else: ""}"}
                 phx-click="select_pipeline_stage" phx-value-stage={stage}>
              <div style="font-size:8px;color:#4b5563;margin-bottom:2px;"><%= step %></div>
              <div style="font-size:10px;font-weight:700;color:var(--text-secondary);line-height:1.2;margin-bottom:2px;"><%= name %></div>
              <div style="font-size:9px;color:#374151;"><%= signal %></div>
              <div class={"pipe-dot #{pipe_dot_class(lv)}"}></div>
            </div>
            <div class="pipe-connector">→</div>
          <% end %>

          <%!-- Lockdown divider --%>
          <div style="flex-shrink:0;display:flex;flex-direction:column;align-items:center;justify-content:center;margin:0 8px;gap:3px;">
            <div style="width:1px;height:28px;background:var(--border);"></div>
            <div style="font-size:8px;text-transform:uppercase;letter-spacing:0.08em;color:#f87171;writing-mode:vertical-rl;transform:rotate(180deg);">LOCK</div>
            <div style="width:1px;height:28px;background:var(--border);"></div>
          </div>

          <%= for {stage, step, name, signal} <- pipeline_stages_lockdown() do %>
            <% lv = stage_level(stage, assigns) %>
            <div class={"pipe-node #{pipe_level_class(lv)} #{if @pipeline_stage == stage, do: "pipe-node-selected", else: ""}"}
                 phx-click="select_pipeline_stage" phx-value-stage={stage}>
              <div style="font-size:8px;color:#4b5563;margin-bottom:2px;"><%= step %></div>
              <div style="font-size:10px;font-weight:700;color:var(--text-secondary);line-height:1.2;margin-bottom:2px;"><%= name %></div>
              <div style="font-size:9px;color:#374151;"><%= signal %></div>
              <div class={"pipe-dot #{pipe_dot_class(lv)}"}></div>
            </div>
            <% if stage != "unlock" do %>
              <div class="pipe-connector">→</div>
            <% end %>
          <% end %>
        </div>

        <%!-- Detail panel --%>
        <%= if @pipeline_stage do %>
          <div style="margin-top:12px;padding:12px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;animation:fadeIn 0.25s ease-out;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
              <span style="font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-secondary);">
                <%= pipe_stage_title(@pipeline_stage) %>
              </span>
              <button phx-click="select_pipeline_stage" phx-value-stage={@pipeline_stage}
                      style="color:var(--text-secondary);background:none;border:none;cursor:pointer;font-size:16px;">×</button>
            </div>
            <%= render_stage_detail(assigns) %>
          </div>
        <% end %>
      </div>

      <div class="grid-2" style="margin-top:12px;">
        <div class="card">
          <div class="card-title">Pipeline Health</div>
          <div class="grid-2" style="gap:8px;">
            <div>
              <div class="stat-label">Chaos Windows</div>
              <div class="stat-num" style="font-size:20px;"><%= @chaos_windows %></div>
            </div>
            <div>
              <div class="stat-label">Rule Fires</div>
              <div class="stat-num" style={"font-size:20px;color:#{if @rule_fires > 0, do: "#fbbf24", else: "#4ade80"};"}>
                <%= @rule_fires %>
              </div>
            </div>
            <div>
              <div class="stat-label">Decoy Events</div>
              <div class="stat-num" style={"font-size:20px;color:#{if @decoy_events > 0, do: "#fbbf24", else: "#4ade80"};"}>
                <%= @decoy_events %>
              </div>
            </div>
            <div>
              <div class="stat-label">Techniques</div>
              <div class="stat-num" style="font-size:20px;color:#60a5fa;">
                <%= length(@attribution_techniques) %>
              </div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">Demo Actions</div>
          <div style="display:flex;flex-direction:column;gap:8px;">
            <button class="btn btn-primary" phx-click="run_demo" phx-throttle="10000"
                    disabled={@demo_running} style="cursor:pointer;">
              <%= if @demo_running, do: "⏳ Running...", else: "▶ Run Full Demo Sequence" %>
            </button>
            <button class="btn btn-ghost btn-sm" phx-click="run_triage" style="cursor:pointer;"
                    onclick="return false;">
              ⚡ Trigger AI Triage
            </button>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # App: Terminal workspace
  # ---------------------------------------------------------------------------

  defp render_terminal(assigns) do
    ~H"""
    <%
      {capture_label, capture_tone} = telemetry_status(assigns)
      {evidence_label, evidence_tone} = evidence_status(assigns)
      visible_lines = Enum.filter(@terminal_lines, fn line -> terminal_line_tag(line) in @terminal_filters end)
    %>
    <section class="terminal-workspace anim-fade" aria-labelledby="terminal-workspace-title" data-testid="terminal-workspace">
      <header class="terminal-workspace-hero">
        <div>
          <p class="terminal-workspace-kicker">Astartis &times; Codex</p>
          <h1 class="terminal-workspace-title" id="terminal-workspace-title">Terminal</h1>
          <p class="terminal-workspace-subtitle">A local, auditable workspace for operations signals, evidence, and safe developer commands.</p>
        </div>
        <div class="terminal-dock-status" aria-label="Terminal evidence state">
          <span class={"terminal-state-chip terminal-state-chip--#{capture_tone}"}>Telemetry: <%= capture_label %></span>
          <span class={"terminal-state-chip terminal-state-chip--#{evidence_tone}"}>Evidence: <%= evidence_label %></span>
        </div>
      </header>

      <div class="terminal-status-grid" aria-label="Terminal status summary">
        <article class="terminal-status-card">
          <span class="terminal-status-card-label">Telemetry source</span>
          <span class={"terminal-state-chip terminal-state-chip--#{capture_tone}"}><%= capture_label %></span>
          <span class="terminal-status-card-note">
            <%= cond do %>
              <% @packet_capture_running and @packet_capture_mode == "live" -> %>
                <%= @packet_windows %> entropy windows from <%= if @packet_capture_adapter == "", do: "the active adapter", else: @packet_capture_adapter %>
              <% @packet_capture_mode == "synthetic" -> %>
                Simulation data is labelled and kept separate from live evidence.
              <% true -> %>
                No packet metadata is being collected right now.
            <% end %>
          </span>
        </article>
        <article class="terminal-status-card">
          <span class="terminal-status-card-label">Evidence freshness</span>
          <span class={"terminal-state-chip terminal-state-chip--#{evidence_tone}"}><%= evidence_label %></span>
          <span class="terminal-status-card-note"><%= @chain_length %> audit-chain entries &middot; <%= if @chain_valid, do: "hash chain verified", else: "verification required" %><br/>View label: <%= @evidence_window_label %> (presentation only)</span>
        </article>
        <article class="terminal-status-card">
          <span class="terminal-status-card-label">Console feed</span>
          <strong class="terminal-status-card-value"><%= length(visible_lines) %> visible events</strong>
          <span class="terminal-status-card-note"><%= terminal_latest_label(@terminal_lines) %></span>
        </article>
      </div>

      <section class="terminal-console" aria-labelledby="terminal-console-title">
        <div class="terminal-console-toolbar">
          <div>
            <h2 class="terminal-console-title" id="terminal-console-title">Evidence stream</h2>
            <p class="terminal-console-description">Filters only change this workspace view. Source events and audit evidence are retained by Astartis.</p>
          </div>
          <div class="terminal-console-filters" aria-label="Terminal filters">
            <%= for tag <- ~w(TERM PACKET RULE WORM AGENT AI AUDIT NAC ZT DECOY SANDBOX TICK) do %>
              <button phx-click="toggle_terminal_filter" phx-value-tag={tag}
                      class={"terminal-filter-btn #{if tag in @terminal_filters, do: "", else: "off"}"}
                      style={"color:#{terminal_tag_color(tag)};"}
                      type="button">
                <%= tag %>
              </button>
            <% end %>
          </div>
        </div>

        <div class="terminal-log" aria-live="polite" aria-label="Astartis event log">
          <%= if Enum.empty?(visible_lines) do %>
            <div class="terminal-empty">No events match the active filters yet. Try enabling a source or run <span class="mono">help</span> below.</div>
          <% else %>
            <%= for line <- visible_lines do %>
              <% tag = terminal_line_tag(line) %>
              <div class="terminal-line" title={terminal_line_text(line)}>
                <span class="terminal-line-time"><%= terminal_line_timestamp(line) %></span>
                <span class="terminal-line-tag" style={"--terminal-tag:#{terminal_tag_color(tag)}"}>[<%= tag %>]</span>
                <span class="terminal-line-text"><%= terminal_line_text(line) %></span>
              </div>
            <% end %>
          <% end %>
        </div>

        <%= if @terminal_cmd_output do %>
          <div class="terminal-command-output"><%= @terminal_cmd_output %></div>
        <% end %>

        <div class="terminal-command-row">
          <span class="terminal-prompt">astartis &gt;</span>
          <input id="terminal-input" class="terminal-input" phx-hook="TermInput"
                 placeholder="Try help, status, or ipconfig /all (read-only allowlist)" autocomplete="off" spellcheck="false" />
        </div>
      </section>
    </section>
    """
  end

  # ---------------------------------------------------------------------------
  # App: Astartis x Codex developer control plane
  # ---------------------------------------------------------------------------

  defp render_codex(assigns) do
    ~H"""
    <%
      {capture_label, capture_tone} = telemetry_status(assigns)
      {evidence_label, evidence_tone} = evidence_status(assigns)
    %>
    <section class="terminal-workspace codex-workspace anim-fade" aria-labelledby="codex-workspace-title">
      <header class="terminal-workspace-hero">
        <div>
          <p class="terminal-workspace-kicker">Developer evidence control plane</p>
          <h1 class="terminal-workspace-title" id="codex-workspace-title">Astartis &times; Codex</h1>
          <p class="terminal-workspace-subtitle">Astartis remains the local enforcement authority. Codex reads bounded evidence, explains decisions, and helps developers verify the smallest secure remediation.</p>
        </div>
        <div class="terminal-dock-status" aria-label="Astartis and Codex evidence state">
          <span class={"terminal-state-chip terminal-state-chip--#{capture_tone}"}>Telemetry: <%= capture_label %></span>
          <span class={"terminal-state-chip terminal-state-chip--#{evidence_tone}"}>Evidence: <%= evidence_label %></span>
        </div>
      </header>

      <section class="card" aria-labelledby="runtime-sample-title" style="border-left:4px solid #0f62fe;margin-bottom:14px;">
        <div style="display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap;">
          <div>
            <div class="card-title" id="runtime-sample-title" style="font-size:17px;color:#161616;">Live local runtime sample</div>
            <p style="font-size:11px;color:var(--text-secondary);line-height:1.65;margin-top:5px;max-width:760px;">
              A bounded, read-only point-in-time sample from this device. It is requested when this workspace or its local bridge connects and when you choose Refresh; it is not a continuous telemetry feed.
            </p>
          </div>
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <%= if @runtime_status_state == "requesting" do %>
              <span class="terminal-state-chip terminal-state-chip--neutral">REQUESTING SAMPLE</span>
            <% else %>
              <span class="terminal-state-chip terminal-state-chip--live">LIVE LOCAL &middot; ON DEMAND</span>
            <% end %>
            <button class="btn btn-secondary btn-sm" phx-click="refresh_runtime_status" type="button" style="cursor:pointer;">Refresh sample</button>
          </div>
        </div>

        <%= if is_map(@runtime_status) do %>
          <% runtime = @runtime_status %>
          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:11px;font-size:10px;color:var(--text-secondary);">
            <span>Sampled: <strong style="color:var(--text-primary);"><%= runtime_sample_time(runtime_value(runtime, "sampled_at_ms")) %></strong></span>
            <span>Mode: <strong class="mono" style="color:#0f62fe;"><%= runtime_mode_label(runtime_value(runtime, "mode")) %></strong></span>
            <%= if @runtime_status_state == "requesting" do %>
              <span style="color:#8a6d00;">Showing the previous sample until the new response arrives.</span>
            <% end %>
          </div>

          <div style="display:grid;grid-template-columns:repeat(4,minmax(138px,1fr));gap:9px;margin-top:12px;">
            <div style="padding:10px;border:1px solid var(--border);background:#f8f9fb;">
              <div class="mono" style="font-size:9px;color:var(--text-secondary);">CPU</div>
              <div style="font-size:18px;font-weight:700;color:#161616;margin-top:3px;"><%= runtime_percent(runtime_value(runtime, "cpu_percent")) %></div>
              <div style="font-size:10px;color:var(--text-secondary);margin-top:3px;"><%= runtime_number(runtime_value(runtime, "cpu_cores"), 0) %> logical cores</div>
            </div>
            <div style="padding:10px;border:1px solid var(--border);background:#f8f9fb;">
              <div class="mono" style="font-size:9px;color:var(--text-secondary);">MEMORY</div>
              <div style="font-size:18px;font-weight:700;color:#161616;margin-top:3px;"><%= runtime_percent(runtime_value(runtime, "memory_percent")) %></div>
              <div style="font-size:10px;color:var(--text-secondary);margin-top:3px;"><%= runtime_gib(runtime_value(runtime, "memory_used_gb")) %> / <%= runtime_gib(runtime_value(runtime, "memory_total_gb")) %></div>
            </div>
            <div style="padding:10px;border:1px solid var(--border);background:#f8f9fb;">
              <div class="mono" style="font-size:9px;color:var(--text-secondary);">DISK</div>
              <div style="font-size:18px;font-weight:700;color:#161616;margin-top:3px;"><%= runtime_percent(runtime_value(runtime, "disk_percent")) %></div>
              <div style="font-size:10px;color:var(--text-secondary);margin-top:3px;"><%= runtime_gib(runtime_value(runtime, "disk_free_gb")) %> free</div>
            </div>
            <div style="padding:10px;border:1px solid var(--border);background:#f8f9fb;">
              <div class="mono" style="font-size:9px;color:var(--text-secondary);">NETWORK</div>
              <div style="font-size:18px;font-weight:700;color:#161616;margin-top:3px;"><%= runtime_mbps(runtime_value(runtime, "network_mbps")) %></div>
              <div style="font-size:10px;color:var(--text-secondary);margin-top:3px;">sampled throughput</div>
            </div>
          </div>

          <div class="grid-2" style="margin-top:12px;">
            <div style="border:1px solid var(--border);padding:10px;">
              <div class="mono" style="font-size:10px;color:var(--text-secondary);margin-bottom:5px;">LOCAL DEPENDENCY PROBES</div>
              <div class="fw-row"><span class="fw-id">OLLAMA</span><span class="fw-desc">Local model endpoint</span><span class="fw-src" style={"color:#{runtime_flag_color(runtime_value(runtime, "ollama_online"))};"}><%= runtime_online_label(runtime_value(runtime, "ollama_online")) %></span></div>
              <div class="fw-row"><span class="fw-id">CLAMAV</span><span class="fw-desc">Daemon probe</span><span class="fw-src" style={"color:#{runtime_flag_color(runtime_value(runtime, "clamd_online"))};"}><%= runtime_online_label(runtime_value(runtime, "clamd_online")) %></span></div>
              <div class="fw-row"><span class="fw-id">NPCAP</span><span class="fw-desc">Driver installed</span><span class="fw-src" style={"color:#{runtime_flag_color(runtime_value(runtime, "npcap_installed"))};"}><%= runtime_presence_label(runtime_value(runtime, "npcap_installed")) %></span></div>
              <div class="fw-row"><span class="fw-id">NPCAP</span><span class="fw-desc">Service state</span><span class="fw-src" style={"color:#{runtime_flag_color(runtime_value(runtime, "npcap_service_running"))};"}><%= runtime_service_label(runtime_value(runtime, "npcap_service_running")) %></span></div>
              <div class="fw-row"><span class="fw-id">BRIDGE</span><span class="fw-desc">Current privilege token</span><span class="fw-src" style={"color:#{runtime_privilege_color(runtime_value(runtime, "bridge_elevated"))};"}><%= runtime_privilege_label(runtime_value(runtime, "bridge_elevated")) %></span></div>
            </div>

            <div style="border:1px solid var(--border);padding:10px;">
              <div class="mono" style="font-size:10px;color:var(--text-secondary);margin-bottom:5px;">ASTARTIS WORKLOAD EVIDENCE</div>
              <div class="fw-row"><span class="fw-id">FLEET</span><span class="fw-desc">Loaded / actively running</span><span class="fw-src"><%= runtime_number(runtime_value(runtime, "agents_loaded"), 0) %> / <%= runtime_number(runtime_value(runtime, "agents_running"), 0) %></span></div>
              <div class="fw-row"><span class="fw-id">QUEUE</span><span class="fw-desc">Pending agent work</span><span class="fw-src"><%= runtime_number(runtime_value(runtime, "agent_queue_depth"), 0) %></span></div>
              <div class="fw-row"><span class="fw-id">TASKS</span><span class="fw-desc">Completed / failed</span><span class="fw-src"><%= runtime_number(runtime_value(runtime, "agent_completed_tasks"), 0) %> / <%= runtime_number(runtime_value(runtime, "agent_failed_tasks"), 0) %></span></div>
              <div class="fw-row"><span class="fw-id">RULES</span><span class="fw-desc">Rule-engine fires</span><span class="fw-src"><%= runtime_number(runtime_value(runtime, "rule_fires"), 0) %></span></div>
              <div class="fw-row"><span class="fw-id">AUDIT</span><span class="fw-desc">Audit-chain records</span><span class="fw-src"><%= runtime_number(runtime_value(runtime, "audit_chain_length"), 0) %></span></div>
            </div>
          </div>
        <% else %>
          <div style="margin-top:12px;padding:12px;border:1px dashed var(--border);font-size:11px;color:var(--text-secondary);">
            <%= if @runtime_status_state == "requesting" do %>
              Collecting a one-time local sample. This workspace will show it when the bridge returns the result.
            <% else %>
              Awaiting the first local sample from the Astartis bridge. Select Refresh to request one again.
            <% end %>
          </div>
        <% end %>
      </section>

      <div class="card" style="border-left:4px solid #0f62fe;">
        <div style="display:flex;justify-content:space-between;gap:18px;align-items:flex-start;flex-wrap:wrap;">
          <div style="max-width:720px;">
            <div class="card-title" style="font-size:17px;color:#161616;">Policy evidence, made actionable where developers work</div>
            <div style="font-size:12px;color:var(--text-secondary);margin-top:6px;line-height:1.7;">
              The Astartis engine remains the enforcement authority. The local Codex plugin reads its evidence,
              runs only safe simulations, and helps developers create, test, and verify the smallest secure remediation.
            </div>
          </div>
          <span class="terminal-state-chip terminal-state-chip--verified">LOCAL MCP &middot; SAFE READ CONTRACT</span>
        </div>
      </div>

      <div class="card" style={"border-left:4px solid #{if @packet_capture_running, do: "#24a148", else: "#8d8d8d"};margin-bottom:14px;"}>
        <div style="display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;">
          <div>
            <div class="card-title" style="margin-bottom:3px;">Live Npcap sensor</div>
            <div style="font-size:12px;color:var(--text-secondary);">
              <%= if @packet_capture_running do %>
                <strong style="color:#42be65;">● CAPTURING <%= String.upcase(@packet_capture_mode) %></strong>
                &nbsp;·&nbsp; <span class="mono"><%= @packet_capture_adapter %></span>
                &nbsp;·&nbsp; <%= @packet_windows %> entropy windows
              <% else %>
                <strong>● OFF</strong> — no packet data is collected until you start it.
              <% end %>
            </div>
            <div style="font-size:10px;color:var(--text-secondary);margin-top:5px;">Local metadata analysis only: Astartis measures entropy windows and audits decisions; it does not upload packet payloads.</div>
          </div>
          <%= if @packet_capture_running do %>
            <button class="btn btn-danger" phx-click="packet_capture_stop" style="cursor:pointer;">Stop capture</button>
          <% else %>
            <button class="btn btn-primary" phx-click="packet_capture_start" style="cursor:pointer;">Start live capture</button>
          <% end %>
        </div>
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-title">Live Astartis Evidence Available to Codex</div>
          <div class="fw-row">
            <span class="fw-id">AUDIT</span>
            <span class="fw-desc">Audit chain</span>
            <span class={"fw-src #{if @chain_valid, do: "badge-green", else: "badge-red"}"}><%= if @chain_valid, do: "VALID", else: "VERIFY" %></span>
          </div>
          <div class="fw-row">
            <span class="fw-id">WORM</span>
            <span class="fw-desc">Immutable recovery evidence</span>
            <span class={"fw-src #{if @worm_locked, do: "badge-red", else: "badge-green"}"}><%= if @worm_locked, do: "LOCKED", else: "PROTECTED" %></span>
          </div>
          <div class="fw-row">
            <span class="fw-id">ZT</span>
            <span class="fw-desc">NAC and Zero Trust policy decisions</span>
            <span class="fw-src">SIMULATE</span>
          </div>
          <div class="fw-row">
            <span class="fw-id">SWARM</span>
            <span class="fw-desc">Security-agent health and queue evidence</span>
            <span class="fw-src"><%= length(@agent_statuses || []) %> AGENTS</span>
          </div>
        </div>

        <div class="card">
          <div class="card-title">Safe Tool Contract</div>
          <div style="font-size:11px;color:var(--text-secondary);line-height:1.75;">
            Codex can read posture and attribution, simulate NAC admission and Zero Trust access, and run deterministic Proof Mode.
          </div>
          <div style="margin-top:12px;padding:10px;border-left:3px solid #f1c21b;background:#fff1c2;font-size:11px;color:#684e00;line-height:1.65;">
            Guardrail: the plugin never exposes firewall blocking, quarantine, WORM unlock, or arbitrary agent execution.
            Every Proof Mode result is labelled as a local simulation.
          </div>
          <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap;">
            <button class="btn btn-primary btn-sm" phx-click="switch_app" phx-value-app="nac" style="cursor:pointer;">Inspect NAC / Zero Trust</button>
            <button class="btn btn-secondary btn-sm" phx-click="switch_app" phx-value-app="audit" style="cursor:pointer;">View audit evidence</button>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Proof Mode &mdash; deterministic developer incident walkthrough</div>
        <div style="display:grid;grid-template-columns:repeat(4,minmax(130px,1fr));gap:9px;margin-top:12px;">
          <div style="padding:11px;border-radius:7px;background:rgba(69,137,255,0.11);border:1px solid rgba(69,137,255,0.24);">
            <div class="mono" style="color:#93c5fd;font-size:10px;">01 / REPRODUCE</div>
            <div style="font-size:11px;margin-top:5px;">Non-compliant contractor laptop requests eGov access.</div>
          </div>
          <div style="padding:11px;border-radius:7px;background:rgba(245,158,11,0.10);border:1px solid rgba(245,158,11,0.25);">
            <div class="mono" style="color:#fcd34d;font-size:10px;">02 / DECIDE</div>
            <div style="font-size:11px;margin-top:5px;">NAC and Zero Trust deny the device and citizen-record request.</div>
          </div>
          <div style="padding:11px;border-radius:7px;background:rgba(168,85,247,0.10);border:1px solid rgba(168,85,247,0.25);">
            <div class="mono" style="color:#d8b4fe;font-size:10px;">03 / EXPLAIN</div>
            <div style="font-size:11px;margin-top:5px;">Codex turns returned evidence into a minimal remediation plan.</div>
          </div>
          <div style="padding:11px;border-radius:7px;background:rgba(16,185,129,0.10);border:1px solid rgba(16,185,129,0.25);">
            <div class="mono" style="color:#6ee7b7;font-size:10px;">04 / VERIFY</div>
            <div style="font-size:11px;margin-top:5px;">Astartis returns attribution, WORM, and audit-chain evidence.</div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Start in Codex</div>
        <div class="mono" style="margin-top:8px;padding:12px;background:#f4f4f4;border:1px solid #dde1e6;border-radius:0;color:#161616;font-size:11px;white-space:pre-wrap;">Run Astartis Proof Mode. Explain why the device and resource request were denied, propose the smallest remediation plan, and tell me how to verify the fix.</div>
        <div style="font-size:10px;color:var(--text-secondary);margin-top:8px;">Plugin path: <span class="mono">plugins/astartis-control-plane</span> &middot; uses the existing local Astartis bridge.</div>
      </div>
    </section>
    """
  end

  # ---------------------------------------------------------------------------
  # App: NAC / Zero Trust Center
  # ---------------------------------------------------------------------------

  defp render_nac(assigns) do
    ~H"""
    <div class="anim-fade">
      <div class="section-header">
        🔐 NAC / Zero Trust Access Control
        <span class="granite-badge">LOCAL AI</span>
      </div>
      <div class="grid-2">
        <%!-- NAC Workflow --%>
        <div>
          <div class="card">
            <div class="card-title">NAC Workflow — 8-Step Access</div>

            <%!-- Device sim form --%>
            <p style="font-size:11px;color:var(--text-secondary);line-height:1.45;margin:0 0 10px;">
              Deterministic local policy evaluation. It exercises Astartis NAC logic and does not admit a device to a physical network.
            </p>
            <div style="margin-bottom:12px;padding:10px;background:var(--bg-secondary);border-radius:6px;">
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.07em;color:var(--text-secondary);margin-bottom:8px;">
                Simulate Device
              </div>
              <form phx-submit="nac_simulate" style="display:flex;flex-direction:column;gap:8px;">
                <div style="display:flex;gap:8px;">
                  <input name="mac" type="text" class="input" style="flex:1;"
                         placeholder="MAC (aa:bb:cc:dd:ee:ff)"
                         value={@nac_device_mac} />
                  <select name="type" class="input" aria-label="Device profile">
                    <option value="BYOD" selected={@nac_device_type == "BYOD"}>BYOD - non-compliant</option>
                    <option value="CORP" selected={@nac_device_type == "CORP"}>Corporate - compliant</option>
                    <option value="IOT" selected={@nac_device_type == "IOT"}>IoT - non-compliant</option>
                  </select>
                </div>
                <select name="ssid" class="input" aria-label="Policy zone">
                  <%= if Enum.empty?(@nac_ssids) do %>
                    <option value="eGov">eGov - enterprise policy zone</option>
                  <% else %>
                    <%= for ssid <- @nac_ssids do %>
                      <option value={ssid["ssid_name"]} selected={@nac_selected_ssid == ssid["ssid_name"] || (@nac_selected_ssid == nil && ssid["ssid_name"] == "eGov")}>
                        <%= ssid["ssid_name"] %> - <%= ssid["posture"] %> - <%= ssid["vlan_id"] %>
                      </option>
                    <% end %>
                  <% end %>
                </select>
                <button type="submit" class="btn btn-primary btn-sm" style="cursor:pointer;">
                  ▶ Run NAC Workflow
                </button>
              </form>
            </div>

            <%!-- 8-step track --%>
            <div style="position:relative;" id="nac-track" phx-hook="NACProgress">
              <div class="nac-line"></div>
              <%= if @nac_step > 0 do %>
                <div class="nac-figure" style={"left:#{nac_step_pct(@nac_step)}%;"}>🚶</div>
              <% end %>
              <div class="nac-track">
                <%= for {step_num, label} <- nac_steps() do %>
                  <div class={"nac-step #{nac_step_class(step_num, @nac_step, @nac_result)}"}>
                    <div class="nac-step-circle"><%= step_num %></div>
                    <div class="nac-step-label"><%= label %></div>
                  </div>
                <% end %>
              </div>
            </div>

            <%!-- Result --%>
            <%= if @nac_result && is_map(@nac_result) do %>
              <% result = @nac_result["result"] || "DENY" %>
              <div class="anim-slide" style={"margin-top:12px;padding:10px;background:#{nac_result_bg(result)};border:1px solid #{nac_result_border(result)};border-radius:6px;"}>
                <div style={"font-size:13px;font-weight:700;color:#{nac_result_color(result)}"}>
                  <%= nac_decision_icon(result) %> <%= result %>
                </div>
                <div style="display:none;">
                  Device: <strong style="color:var(--text-primary);"><%= @nac_result["device_name"] || @nac_result["device_mac"] %></strong>
                  &nbsp;·&nbsp; VLAN: <strong style="color:#60a5fa;"><%= @nac_result["vlan"] %></strong>
                  &nbsp;·&nbsp; Role: <strong style="color:#a78bfa;"><%= @nac_result["role"] %></strong>
                </div>
                <div style="font-size:11px;color:var(--text-secondary);margin-top:5px;line-height:1.6;">
                  Device: <strong style="color:var(--text-primary);"><%= @nac_result["device_name"] || @nac_result["device_mac"] %></strong><br/>
                  Assigned VLAN: <strong style="color:#0f62fe;"><%= @nac_result["assigned_vlan"] || "none" %></strong>
                  &middot; Role: <strong style="color:#8a3ffc;"><%= @nac_result["assigned_role"] || "none" %></strong>
                </div>
                <%= if List.wrap(@nac_result["accessible_resources"]) != [] do %>
                  <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap;">
                    <%= for resource <- List.wrap(@nac_result["accessible_resources"]) do %>
                      <span class="badge badge-green"><%= resource %></span>
                    <% end %>
                  </div>
                <% end %>
                <%= if @nac_result["remediation_reason"] not in [nil, ""] do %>
                  <div style="margin-top:7px;font-size:10px;color:var(--text-secondary);">
                    Remediation: <%= @nac_result["remediation_reason"] %>
                  </div>
                <% end %>
              </div>
            <% end %>
          </div>
        </div>

        <%!-- Zero Trust Evaluate + Compliance --%>
        <div>
          <div class="card">
            <div class="card-title">Zero Trust Policy Evaluation</div>
            <p style="font-size:11px;color:var(--text-secondary);line-height:1.45;margin:8px 0 10px;">
              Deterministic local access-policy evaluation. It does not query an identity provider or enforce a production network rule.
            </p>
            <form phx-submit="zt_evaluate" style="display:flex;flex-direction:column;gap:8px;margin-bottom:10px;">
              <div style="display:flex;gap:8px;">
                <input name="user_id" type="text" class="input" style="flex:1;" value="demo.contractor" aria-label="User ID" />
                <input name="device_id" type="text" class="input" style="flex:1;" value="02:42:ac:11:00:09" aria-label="Device ID" />
              </div>
              <div style="display:flex;gap:8px;">
                <input name="source_ip" type="text" class="input" style="flex:1;" value="10.200.0.25" aria-label="Source IP" />
                <input name="destination_ip" type="text" class="input" style="flex:1;" value="10.200.0.10" aria-label="Destination IP" />
              </div>
              <div style="display:flex;gap:8px;">
                <input name="requested_resource" type="text" class="input" style="flex:1;" value="citizen-records" aria-label="Requested resource" />
                <select name="ssid_name" class="input" style="flex:1;" aria-label="Policy zone">
                  <option value="eGov">eGov</option>
                  <option value="SmartBots">SmartBots</option>
                  <option value="Astartis-Admin">Astartis-Admin</option>
                </select>
              </div>
              <select name="legacy_resource" class="input" style="display:none;">
                <option value="file-server">file-server</option>
                <option value="db-server">db-server</option>
                <option value="vpn">vpn</option>
                <option value="admin-console">admin-console</option>
              </select>
              <select name="legacy_action" class="input" style="display:none;">
                <option value="read">read</option>
                <option value="write">write</option>
                <option value="admin">admin</option>
              </select>
              <button type="submit" class="btn btn-primary btn-sm" style="cursor:pointer;">Evaluate Zero Trust policy</button>
              <button type="submit" class="btn btn-primary btn-sm" style="display:none;">
                🔐 Evaluate Zero Trust
              </button>
            </form>
            <%= cond do %>
              <% @zt_result == nil -> %>
                <div style="color:var(--text-secondary);font-size:11px;">No policy evaluation yet.</div>
              <% @zt_result == :pending -> %>
                <div style="color:#fbbf24;font-size:11px;">⏳ Evaluating...</div>
              <% true -> %>
                <% zt = @zt_result %>
                <% decision = zt["decision"] || "DENY" %>
                <div class="anim-slide" style="display:none;">
                  <div class={"badge #{if zt["access_granted"], do: "badge-green", else: "badge-red"}"} style="font-size:12px;padding:4px 10px;margin-bottom:8px;">
                    <%= if zt["access_granted"], do: "✅ ACCESS GRANTED", else: "🚫 ACCESS DENIED" %>
                  </div>
                  <div style="font-size:11px;color:var(--text-secondary);">
                    Token: <span class="mono" style="color:#60a5fa;"><%= zt["token_id"] %></span><br/>
                    Reason: <span style="color:var(--text-primary);"><%= zt["reason"] %></span>
                  </div>
                  <%= if zt["resources"] && length(zt["resources"]) > 0 do %>
                    <div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap;">
                      <%= for r <- zt["resources"] do %>
                        <span class="badge badge-blue"><%= r %></span>
                      <% end %>
                    </div>
                  <% end %>
                </div>
                <div class="anim-slide">
                  <div class={"badge #{zt_decision_badge(decision)}"} style="font-size:12px;padding:4px 10px;margin-bottom:8px;">
                    <%= decision %>
                  </div>
                  <div style="font-size:11px;color:var(--text-secondary);line-height:1.65;">
                    Trust score: <strong style="color:var(--text-primary);"><%= zt["trust_score"] %>/100</strong><br/>
                    Subject: <span class="mono" style="color:#0f62fe;"><%= zt["user_id"] %></span> on <span class="mono"><%= zt["device_id"] %></span><br/>
                    Route: <span class="mono"><%= zt["source_ip"] %></span> &rarr; <span class="mono"><%= zt["destination_ip"] %></span><br/>
                    Resource: <strong style="color:var(--text-primary);"><%= zt["requested_resource"] %></strong> &middot; Zone: <%= zt["ssid_name"] %>
                  </div>
                </div>
            <% end %>
          </div>

          <div class="card">
            <div class="card-title">NIST ZTA Pillars</div>
            <%= for {pillar, desc, module} <- nist_zta_mappings() do %>
              <div class="fw-row">
                <span class="fw-id"><%= pillar %></span>
                <span class="fw-desc"><%= desc %></span>
                <span class="fw-src" style="font-size:9px;"><%= module %></span>
              </div>
            <% end %>
          </div>
        </div>
      </div>
    </div>
    """
  end


  # ---------------------------------------------------------------------------
  # Helpers: push_terminal
  # ---------------------------------------------------------------------------

  defp push_terminal(socket, tag, text) do
    ts = DateTime.utc_now() |> Calendar.strftime("%H:%M:%S.%f") |> String.slice(0, 12)
    line = %{tag: tag, text: text, ts: ts}
    lines = Enum.take((socket.assigns[:terminal_lines] || []) ++ [line], -300)

    socket
    |> assign(terminal_lines: lines)
    |> push_event("terminal_line", line)
  end

  defp telemetry_status(assigns) do
    cond do
      assigns[:packet_capture_running] && assigns[:packet_capture_mode] == "live" ->
        {"Live Npcap", "live"}

      assigns[:packet_capture_mode] == "synthetic" ->
        {"Simulation", "simulation"}

      assigns[:capture_action_state] == "starting" ->
        {"Starting", "neutral"}

      assigns[:capture_error] ->
        {"Needs review", "review"}

      true ->
        {"Offline", "neutral"}
    end
  end

  defp evidence_status(assigns) do
    chain_length = assigns[:chain_length] || 0

    cond do
      assigns[:chain_valid] && assigns[:packet_capture_running] && assigns[:packet_capture_mode] == "live" ->
        {"Live and verified", "live"}

      assigns[:chain_valid] && chain_length > 0 ->
        {"Verified history", "verified"}

      chain_length > 0 ->
        {"Review required", "review"}

      true ->
        {"Awaiting evidence", "neutral"}
    end
  end

  # Runtime evidence is deliberately requested only on workspace connection or
  # through the explicit Refresh action. Keep expensive local probes out of
  # the 500 ms posture stream and label this data as a point-in-time sample.
  defp request_runtime_status do
    AstartisWeb.Core.AstartisPort.send_command(%{"cmd" => "runtime_status", "args" => %{}})
  end

  defp runtime_status_summary(data) do
    "runtime sample mode=#{runtime_mode_label(runtime_value(data, "mode"))} " <>
      "cpu=#{runtime_percent(runtime_value(data, "cpu_percent"))} " <>
      "agents=#{runtime_number(runtime_value(data, "agents_loaded"), 0)}/#{runtime_number(runtime_value(data, "agents_running"), 0)} " <>
      "queue=#{runtime_number(runtime_value(data, "agent_queue_depth"), 0)}"
  end

  defp runtime_value(status, key) when is_map(status), do: Map.get(status, key)
  defp runtime_value(_status, _key), do: nil

  defp runtime_number(nil, _precision), do: "—"
  defp runtime_number(value, precision) when is_number(value) and precision == 0,
    do: Integer.to_string(round(value))
  defp runtime_number(value, precision) when is_number(value),
    do: :erlang.float_to_binary(Float.round(value * 1.0, precision), decimals: precision)
  defp runtime_number(_value, _precision), do: "—"

  defp runtime_percent(value) when is_number(value), do: runtime_number(value, 1) <> "%"
  defp runtime_percent(_value), do: "—"

  defp runtime_gib(value) when is_number(value), do: runtime_number(value, 1) <> " GiB"
  defp runtime_gib(_value), do: "—"

  defp runtime_mbps(value) when is_number(value), do: runtime_number(value, 1) <> " Mbps"
  defp runtime_mbps(_value), do: "—"

  defp runtime_sample_time(value) when is_number(value) do
    case DateTime.from_unix(trunc(value), :millisecond) do
      {:ok, sampled_at} -> Calendar.strftime(sampled_at, "%Y-%m-%d %H:%M:%S UTC")
      {:error, _reason} -> "unknown"
    end
  end
  defp runtime_sample_time(_value), do: "unknown"

  defp runtime_mode_label("live_local"), do: "LIVE LOCAL"
  defp runtime_mode_label(mode) when is_binary(mode), do: mode |> String.replace("_", " ") |> String.upcase()
  defp runtime_mode_label(_mode), do: "UNKNOWN"

  defp runtime_online_label(true), do: "ONLINE"
  defp runtime_online_label(false), do: "OFFLINE"
  defp runtime_online_label(_value), do: "UNAVAILABLE"

  defp runtime_presence_label(true), do: "INSTALLED"
  defp runtime_presence_label(false), do: "NOT FOUND"
  defp runtime_presence_label(_value), do: "UNAVAILABLE"

  defp runtime_service_label(true), do: "RUNNING"
  defp runtime_service_label(false), do: "STOPPED"
  defp runtime_service_label(_value), do: "UNAVAILABLE"

  defp runtime_privilege_label(true), do: "ELEVATED"
  defp runtime_privilege_label(false), do: "STANDARD USER"
  defp runtime_privilege_label(_value), do: "UNKNOWN"

  defp runtime_flag_color(true), do: "#198038"
  defp runtime_flag_color(false), do: "#da1e28"
  defp runtime_flag_color(_value), do: "#525252"

  defp runtime_privilege_color(true), do: "#198038"
  defp runtime_privilege_color(false), do: "#525252"
  defp runtime_privilege_color(_value), do: "#525252"

  defp terminal_line_tag(line) when is_map(line), do: Map.get(line, :tag) || Map.get(line, "tag") || "SYSTEM"
  defp terminal_line_tag(_), do: "SYSTEM"

  defp terminal_line_text(line) when is_map(line), do: Map.get(line, :text) || Map.get(line, "text") || ""
  defp terminal_line_text(_), do: ""

  defp terminal_line_timestamp(line) when is_map(line), do: Map.get(line, :ts) || Map.get(line, "ts") || "--:--:--"
  defp terminal_line_timestamp(_), do: "--:--:--"

  defp terminal_latest_label([]), do: "No terminal events yet"
  defp terminal_latest_label(lines), do: "Latest event #{terminal_line_timestamp(List.last(lines))} UTC"

  defp clear_capture_start_timer(socket) do
    case socket.assigns[:capture_start_timer] do
      nil -> socket
      timer_ref ->
        Process.cancel_timer(timer_ref)
        assign(socket, capture_start_timer: nil)
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers: assign_state
  # ---------------------------------------------------------------------------

  defp assign_state(socket, data) do
    assign(socket,
      threat_tier:             data["threat_tier"]             || 0,
      threat_tier_name:        data["threat_tier_name"]        || "LOW",
      threat_transitions:      data["threat_transitions"]      || 0,
      worm_locked:             data["worm_locked"]             || false,
      worm_reason:             data["worm_reason"]             || "",
      worm_lock_count:         data["worm_lock_count"]         || 0,
      chain_length:            data["chain_length"]            || 0,
      chain_valid:             Map.get(data, "chain_valid", true),
      chain_head:              data["chain_head"]              || "",
      chaos_K:                 data["chaos_K"]                 || 0.0,
      chaos_anomalous:         data["chaos_anomalous"]         || false,
      chaos_windows:           data["chaos_windows"]           || 0,
      rule_fires:              data["rule_fires"]              || 0,
      worm_triggers:           data["worm_triggers"]           || 0,
      decoy_events:            data["decoy_events"]            || 0,
      sandbox_entries:         data["sandbox_entries"]         || [],
      sandbox_root:            data["sandbox_root"]            || "",
      quarantine_count:        data["quarantine_count"]        || 0,
      active_firewall_blocks:  data["active_firewall_blocks"]  || [],
      unlock_votes_collected:  data["unlock_votes_collected"]  || 0,
      unlock_threshold:        data["unlock_threshold"]        || 3,
      unlock_state:            data["unlock_state"]            || "IDLE",
      unlock_approvers:        data["unlock_approvers"]        || [],
      veeam_lock_state:        data["veeam_lock_state"]        || "UNLOCKED",
      veeam_backup_count:      data["veeam_backup_count"]      || 0,
      veeam_locked_at_ms:      data["veeam_locked_at_ms"]      || 0,
      veeam_integrity_checks:  data["veeam_integrity_checks"]  || 0,
      veeam_locked_by_reason:  data["veeam_locked_by_reason"]  || "",
      packet_capture_running:  Map.get(data, "packet_capture_running", socket.assigns[:packet_capture_running] || false),
      packet_capture_mode:     data["packet_capture_mode"]     || socket.assigns[:packet_capture_mode] || "stopped",
      packet_capture_adapter:  data["packet_capture_adapter"]  || socket.assigns[:packet_capture_adapter] || "",
      packet_windows:          data["packet_windows"]          || socket.assigns[:packet_windows] || 0,
      packet_threat_score:     data["packet_threat_score"]     || socket.assigns[:packet_threat_score] || 0,
      packet_anomalous:        Map.get(data, "packet_anomalous", socket.assigns[:packet_anomalous] || false),
      bridge_elevated:         Map.get(data, "elevated", socket.assigns[:bridge_elevated]),
      agent_statuses:          data["agent_statuses"]          || socket.assigns[:agent_statuses] || [],
      agent_queue_depth:       data["agent_queue_depth"]       || socket.assigns[:agent_queue_depth] || 0
    )
  end

  # ---------------------------------------------------------------------------
  # Helpers: tier conversions
  # ---------------------------------------------------------------------------

  defp tier_int_to_name(0), do: "LOW"
  defp tier_int_to_name(1), do: "MEDIUM"
  defp tier_int_to_name(2), do: "HIGH"
  defp tier_int_to_name(3), do: "CRITICAL"
  defp tier_int_to_name(_), do: "LOW"

  defp tier_name(0), do: "LOW"
  defp tier_name(1), do: "MEDIUM"
  defp tier_name(2), do: "HIGH"
  defp tier_name(3), do: "CRITICAL"
  defp tier_name(_), do: "LOW"

  defp update_chaos_history(current, nil), do: current
  defp update_chaos_history(_current, new_list) when is_list(new_list) do
    Enum.take(new_list, -@chaos_history_max)
  end
  defp update_chaos_history(current, _), do: current

  # ---------------------------------------------------------------------------
  # Helpers: formatting
  # ---------------------------------------------------------------------------

  defp format_bytes(n) when n < 1024,             do: "#{n} B"
  defp format_bytes(n) when n < 1024 * 1024,      do: "#{Float.round(n / 1024, 1)} KB"
  defp format_bytes(n),                            do: "#{Float.round(n / (1024*1024), 1)} MB"

  defp format_expiry(nil), do: "unknown"
  defp format_expiry(expires_at_ms) do
    now_ms = System.system_time(:millisecond)
    remaining_s = div(expires_at_ms - now_ms, 1000)
    cond do
      remaining_s <= 0 -> "expired"
      remaining_s < 60 -> "#{remaining_s}s"
      true             -> "#{div(remaining_s, 60)}m #{rem(remaining_s, 60)}s"
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers: chaos chart
  # ---------------------------------------------------------------------------

  defp chaos_svg_string(history) do
    vw = 600; vh = 100; n = length(history)
    point_str =
      if n < 2, do: "",
      else: (
        step = vw / (n - 1)
        history
        |> Enum.with_index()
        |> Enum.map(fn {k, i} -> "#{Float.round(i * step, 1)},#{Float.round(vh - k * vh, 1)}" end)
        |> Enum.join(" ")
      )
    ty = Float.round(vh * 0.3, 1)
    dot_svg = if n > 0 do
      last_k = List.last(history)
      last_y = Float.round(vh - last_k * vh, 1)
      colour = if last_k > 0.7, do: "#da1e28", else: "#0f62fe"
      ~s(<circle cx="#{vw}" cy="#{last_y}" r="3" fill="#{colour}"/>)
    else "" end
    polyline_svg = if byte_size(point_str) > 0 do
      ~s(<polyline points="#{point_str}" fill="none" stroke="#0f62fe" stroke-width="1.5"/>#{dot_svg})
    else "" end
    ~s(<svg viewBox="0 0 #{vw} #{vh}" width="100%" height="#{vh}" style="display:block;">) <>
    ~s(<rect width="#{vw}" height="#{vh}" fill="#ffffff" stroke="#dde1e6" rx="4"/>) <>
    ~s(<line x1="0" y1="#{ty}" x2="#{vw}" y2="#{ty}" stroke="#da1e28" stroke-width="1" stroke-dasharray="4 3" opacity="0.7"/>) <>
    ~s(<text x="4" y="#{ty - 3}" fill="#da1e28" font-size="9" opacity="0.85">threshold 0.7</text>) <>
    polyline_svg <> "</svg>"
  end

  # ---------------------------------------------------------------------------
  # Helpers: chaos colour mapping
  # ---------------------------------------------------------------------------

  defp k_color(k) when k > 0.7, do: "#f87171"
  defp k_color(k) when k > 0.3, do: "#fbbf24"
  defp k_color(_),               do: "#4ade80"

  defp k_bar_class(k) when k > 0.7, do: "h-bar-red"
  defp k_bar_class(k) when k > 0.3, do: "h-bar-yellow"
  defp k_bar_class(_),               do: "h-bar-green"

  defp k_status_text(k, true)  when k > 0.7, do: "ANOMALOUS — possible C2 tunneling"
  defp k_status_text(k, _)     when k > 0.7, do: "HIGH ENTROPY"
  defp k_status_text(k, _)     when k > 0.3, do: "ELEVATED (monitoring)"
  defp k_status_text(_k, _),                 do: "MONITORING (normal)"

  # Hex colour string → "r,g,b" for rgba() usage (simplified for known palette)
  defp hex_to_rgb_str("#4ade80"), do: "74,222,128"
  defp hex_to_rgb_str("#fbbf24"), do: "251,191,36"
  defp hex_to_rgb_str("#f97316"), do: "249,115,22"
  defp hex_to_rgb_str("#f87171"), do: "248,113,113"
  defp hex_to_rgb_str(_),         do: "100,100,100"

  # ---------------------------------------------------------------------------
  # Helpers: dock items with badge counts
  # ---------------------------------------------------------------------------

  defp dock_items(assigns) do
    defense_badge = (if assigns[:rule_fires] > 0, do: assigns.rule_fires, else: 0)
    decoy_badge   = (if assigns[:decoy_events] > 0, do: assigns.decoy_events, else: 0)
    [
      {"HOME", "overview", "Overview", 0},
      {"CODE", "codex", "Codex workspace", 0},
      {"TERM", "terminal", "Terminal", 0},
      {"NET", "network",  "Network sensor",  0},
      {"DEF", "defense",  "Detections",  defense_badge},
      {"AGT", "agents",   "Agent fleet",   assigns.agent_queue_depth},
      {"SBOX", "sandbox",  "Sandbox",  decoy_badge},
      {"PIPE", "pipeline", "Decision flow", 0},
      {"NAC", "nac",      "NAC & Zero Trust",   0},
      {"RPT", "reports",  "Reports",  0},
      {"AUD", "audit",    "Evidence",    0},
      {"SET", "settings", "Settings", 0},
    ]
  end

  # ---------------------------------------------------------------------------
  # Helpers: sandbox
  # ---------------------------------------------------------------------------

  defp file_icon(%{"type" => "dir"}),  do: "📁"
  defp file_icon(%{"locked" => true}), do: "🔒"
  defp file_icon(entry) do
    path = entry["rel_path"] || ""
    cond do
      String.ends_with?(path, [".conf", ".config", ".cfg", ".ini"]) -> "⚙️"
      String.ends_with?(path, [".log"])                              -> "📋"
      String.ends_with?(path, [".key", "credentials", "id_rsa"])    -> "🔑"
      String.ends_with?(path, [".xlsx", ".csv"])                     -> "📊"
      String.ends_with?(path, [".pdf"])                              -> "📄"
      is_poisoned?(entry)                                            -> "⚠️"
      true                                                           -> "📄"
    end
  end

  defp entry_color(%{"locked" => true}), do: "#fca5a5"
  defp entry_color(_), do: "var(--text-primary)"

  defp agent_description("alert_triage"), do: "Prioritizes security alerts using local fast-tier routing"
  defp agent_description("recon_agent"), do: "Maps network topology and identifies attack surfaces"
  defp agent_description("security_reviewer"), do: "Reviews code and configurations for vulnerabilities"
  defp agent_description("threat_hunter"), do: "Proactively searches for IOCs and APT indicators"
  defp agent_description("vuln_scanner"), do: "Scans systems for known CVEs and misconfigurations"
  defp agent_description("incident_responder"), do: "Coordinates breach response and containment"
  defp agent_description("code_reviewer"), do: "Analyzes source code for security flaws"
  defp agent_description("bug_hunter"), do: "Finds and classifies software vulnerabilities"
  defp agent_description("siem_analyst"), do: "Correlates security events across data sources"
  defp agent_description("report_generator"), do: "Produces executive and technical security reports"
  defp agent_description("patch_validator"), do: "Validates security patches before deployment"
  defp agent_description("forensic_analyst"), do: "Analyzes compromised systems for evidence"
  defp agent_description("compliance_auditor"), do: "Checks regulatory compliance (SOC2, ISO 27001, PCI DSS)"
  defp agent_description("risk_assessor"), do: "Quantifies organizational cyber risk exposure"
  defp agent_description("pentest_orchestrator"), do: "Plans and executes penetration tests"
  defp agent_description("threat_modeler"), do: "Builds attack trees for critical assets"
  defp agent_description("malware_analyst"), do: "Reverse-engineers malicious software"
  defp agent_description("network_mapper"), do: "Discovers network topology and segments"
  defp agent_description("exploit_developer"), do: "Develops proof-of-concept exploits for testing"
  defp agent_description("crypto_auditor"), do: "Audits cryptographic implementations and key management"
  defp agent_description("log_correlator"), do: "Cross-references logs to find attack patterns"
  defp agent_description("deception_engineer"), do: "Designs and deploys honeypots and decoys"
  defp agent_description("soc_analyst"), do: "Monitors security operations center dashboards"
  defp agent_description("intel_curator"), do: "Maintains threat intelligence knowledge base"
  defp agent_description("response_planner"), do: "Creates incident response playbooks"
  defp agent_description("policy_enforcer"), do: "Enforces security policies across infrastructure"
  defp agent_description(_), do: "Autonomous security agent using the local AI runtime"

  defp agent_model_label(model) when is_binary(model) do
    if String.contains?(String.downcase(model), "dense"), do: "Local deep-analysis tier", else: "Local fast tier"
  end
  defp agent_model_label(_), do: "Local AI runtime"

  defp is_poisoned?(entry) do
    tags = entry["tags"] || []
    Enum.any?(tags, &(&1 in ["poisoned", "decoy", "credential_poison", "lateral_movement"]))
  end

  # ---------------------------------------------------------------------------
  # Helpers: NAC
  # ---------------------------------------------------------------------------

  defp nac_steps do
    [
      {1, "CONNECT"}, {2, "802.1X"}, {3, "IDENTITY"},
      {4, "POSTURE"}, {5, "POLICY"}, {6, "RBAC"},
      {7, "MONITOR"}, {8, "DECIDE"}
    ]
  end

  defp nac_step_pct(step) do
    pct = (step - 1) / 7.0 * 100
    max(0.0, min(100.0, pct)) |> Float.round(1)
  end

  defp nac_step_class(step_num, current_step, result) do
    cond do
      result && is_map(result) && step_num < current_step ->
        if result["result"] in ["ALLOW_FULL", "ALLOW_LIMITED"], do: "nac-pass", else: "nac-fail"
      step_num == current_step -> "nac-active"
      step_num == 8 && result && is_map(result) ->
        if result["result"] in ["ALLOW_FULL", "ALLOW_LIMITED"], do: "nac-pass", else: "nac-fail"
      true -> ""
    end
  end

  defp nac_decision_icon("ALLOW_FULL"),        do: "✅"
  defp nac_decision_icon("ALLOW_RESTRICTED"),  do: "⚠️"
  defp nac_decision_icon("QUARANTINE"),         do: "🔒"
  defp nac_decision_icon("DENY"),               do: "🚫"
  defp nac_decision_icon("ALLOW_LIMITED"),     do: "LIMITED"
  defp nac_decision_icon("MFA_REQUIRED"),      do: "MFA"
  defp nac_decision_icon(_),                    do: "?"

  defp nac_result_bg("ALLOW_FULL"),       do: "rgba(16,185,129,0.08)"
  defp nac_result_bg("ALLOW_LIMITED"),    do: "rgba(245,158,11,0.08)"
  defp nac_result_bg("MFA_REQUIRED"),     do: "rgba(245,158,11,0.08)"
  defp nac_result_bg("ALLOW_RESTRICTED"), do: "rgba(245,158,11,0.08)"
  defp nac_result_bg(_),                  do: "rgba(239,68,68,0.08)"

  defp nac_result_border("ALLOW_FULL"),       do: "#10b981"
  defp nac_result_border("ALLOW_LIMITED"),    do: "#f59e0b"
  defp nac_result_border("MFA_REQUIRED"),     do: "#f59e0b"
  defp nac_result_border("ALLOW_RESTRICTED"), do: "#f59e0b"
  defp nac_result_border(_),                  do: "#ef4444"

  defp nac_result_color("ALLOW_FULL"),       do: "#4ade80"
  defp nac_result_color("ALLOW_LIMITED"),    do: "#fbbf24"
  defp nac_result_color("MFA_REQUIRED"),     do: "#fbbf24"
  defp nac_result_color("ALLOW_RESTRICTED"), do: "#fbbf24"
  defp nac_result_color(_),                  do: "#f87171"

  defp zt_decision_badge("ALLOW"), do: "badge-green"
  defp zt_decision_badge(decision) when decision in ["LIMITED", "MFA_REQUIRED"], do: "badge-yellow"
  defp zt_decision_badge(_), do: "badge-red"

  # ---------------------------------------------------------------------------
  # Helpers: audit chain demo blocks
  # ---------------------------------------------------------------------------

  defp build_demo_audit_blocks(0, _), do: []
  defp build_demo_audit_blocks(length, head) do
    events = ["worm_lock", "packet_anomaly", "rule_fire", "ai_triage", "decoy_triggered",
              "firewall_block", "agent_task", "tier_change", "veeam_check", "scan_result"]
    last = min(length, 8)
    Enum.map(0..(last - 1), fn i ->
      %{
        index: length - last + i + 1,
        event: Enum.at(events, rem(i, length(events))),
        hash:  if(i == last - 1, do: head, else: "#{Integer.to_string(i + 1, 16) |> String.pad_leading(8, "0")}abcdef")
      }
    end)
  end

  # ---------------------------------------------------------------------------
  # Helpers: audit event handler
  # ---------------------------------------------------------------------------

  # ---------------------------------------------------------------------------
  # Helpers: terminal tag colour
  # ---------------------------------------------------------------------------

  defp terminal_tag_color("TERM"),   do: "#0f62fe"
  defp terminal_tag_color("PACKET"), do: "#005d5d"
  defp terminal_tag_color("RULE"),   do: "#8a6d00"
  defp terminal_tag_color("WORM"),   do: "#a2191f"
  defp terminal_tag_color("AGENT"),  do: "#0043ce"
  defp terminal_tag_color("AI"),     do: "#6929c4"
  defp terminal_tag_color("AUDIT"),  do: "#198038"
  defp terminal_tag_color("NAC"),    do: "#ba4e00"
  defp terminal_tag_color("ZT"),     do: "#6929c4"
  defp terminal_tag_color("DECOY"),  do: "#9f1853"
  defp terminal_tag_color("SANDBOX"),do: "#0072c3"
  defp terminal_tag_color("TICK"),   do: "#6f6f6f"
  defp terminal_tag_color(_),        do: "#525252"

  # ---------------------------------------------------------------------------
  # Helpers: pipeline stage data
  # ---------------------------------------------------------------------------

  defp pipeline_stages_omidax do
    [
      {"packet",      "STEP 5",  "Packet\nCapture",  "Npcap"},
      {"entropy",     "STEP 5",  "Entropy\nScore",   "Shannon"},
      {"chaos",       "STEP 12", "Chaos K\nScore",   "0-1 Test"},
      {"rules",       "STEP 7",  "Rule\nEngine",     "R01–05"},
      {"tier",        "STEP 6",  "Threat\nTier",     "L/M/H/C"},
      {"zt",          "STEP 8",  "ZT Access\nCheck", "Token"},
    ]
  end

  defp pipeline_stages_dibanet do
    [
      {"decoy",       "STEP 10", "Decoy\nEnv",       "Poison"},
      {"ar",          "STEP 11", "Active\nResponse", "Throttle"},
      {"defense",     "STEP 16", "Qtn +\nFirewall",  "Real"},
      {"attribution", "STEP 13", "Attribution",      "ATT&CK"},
      {"triage",      "STEP 18", "AI\nTriage",       "Granite"},
    ]
  end

  defp pipeline_stages_lockdown do
    [
      {"worm",   "STEP 3",  "WORM\nLock",    "WORM"},
      {"veeam",  "STEP 19", "Veeam/\nIBM",   "Backup"},
      {"unlock", "STEP 17", "12-Eye\nUnlock", "Quorum"},
    ]
  end

  # ---------------------------------------------------------------------------
  # Helpers: Pipeline CSS classes
  # ---------------------------------------------------------------------------

  defp pipe_level_class(:idle),     do: "pipe-node-idle"
  defp pipe_level_class(:active),   do: "pipe-node-active"
  defp pipe_level_class(:critical), do: "pipe-node-critical"

  defp pipe_dot_class(:idle),     do: "pipe-dot-idle"
  defp pipe_dot_class(:active),   do: "pipe-dot-active"
  defp pipe_dot_class(:critical), do: "pipe-dot-critical"

  defp pipe_stage_title("packet"),      do: "Step 5 — Packet Capture (Npcap)"
  defp pipe_stage_title("entropy"),     do: "Step 5 — Entropy Score (Shannon)"
  defp pipe_stage_title("chaos"),       do: "Step 12 — Chaos K Score (0-1 Test)"
  defp pipe_stage_title("rules"),       do: "Step 7 — Rule Engine (RULE-01…RULE-05)"
  defp pipe_stage_title("tier"),        do: "Step 6 — Threat Tier State Machine"
  defp pipe_stage_title("zt"),          do: "Step 8 — Zero-Trust Access Check"
  defp pipe_stage_title("decoy"),       do: "Step 10 — Decoy Environment"
  defp pipe_stage_title("ar"),          do: "Step 11 — Active Response"
  defp pipe_stage_title("defense"),     do: "Step 16 — Quarantine + Firewall Block"
  defp pipe_stage_title("attribution"), do: "Step 13 — Attribution Report"
  defp pipe_stage_title("triage"),      do: "Step 18 — AI Triage (local inference)"
  defp pipe_stage_title("worm"),        do: "Step 3 — WORM Lockdown"
  defp pipe_stage_title("veeam"),       do: "Step 19 — Veeam / IBM Storage"
  defp pipe_stage_title("unlock"),      do: "Step 17 — 12-Eye Unlock Protocol"
  defp pipe_stage_title(s),             do: s

  # ---------------------------------------------------------------------------
  # Pipeline stage level derivation (unchanged from v1)
  # ---------------------------------------------------------------------------

  defp stage_level("packet", assigns) do
    if assigns.chaos_windows > 0, do: :active, else: :idle
  end

  defp stage_level("entropy", assigns) do
    cond do
      assigns.chaos_anomalous   -> :critical
      assigns.chaos_K > 0.3     -> :active
      assigns.chaos_windows > 0 -> :active
      true                      -> :idle
    end
  end

  defp stage_level("chaos", assigns) do
    cond do
      assigns.chaos_anomalous   -> :critical
      assigns.chaos_K > 0.7     -> :critical
      assigns.chaos_K > 0.3     -> :active
      assigns.chaos_windows > 0 -> :active
      true                      -> :idle
    end
  end

  defp stage_level("rules", assigns) do
    cond do
      assigns.worm_triggers > 0 -> :critical
      assigns.rule_fires > 0    -> :active
      true                      -> :idle
    end
  end

  defp stage_level("tier", assigns) do
    case assigns.threat_tier do
      3 -> :critical
      2 -> :critical
      1 -> :active
      _ -> :idle
    end
  end

  defp stage_level("zt", assigns) do
    cond do
      assigns.threat_tier >= 2 -> :critical
      assigns.threat_tier >= 1 -> :active
      assigns.chain_length > 0 -> :active
      true                     -> :idle
    end
  end

  defp stage_level("decoy", assigns) do
    cond do
      assigns.decoy_events >= 3 -> :critical
      assigns.decoy_events > 0  -> :active
      true                      -> :idle
    end
  end

  defp stage_level("ar", assigns) do
    cond do
      assigns.decoy_events >= 3 -> :critical
      assigns.decoy_events > 0  -> :active
      true                      -> :idle
    end
  end

  defp stage_level("defense", assigns) do
    blocks = length(assigns.active_firewall_blocks)
    cond do
      assigns.quarantine_count > 0 and blocks > 0 -> :critical
      assigns.quarantine_count > 0 or blocks > 0  -> :active
      true                                         -> :idle
    end
  end

  defp stage_level("attribution", assigns) do
    cond do
      length(assigns.attribution_techniques) > 0 -> :critical
      assigns.decoy_events > 0                   -> :active
      true                                        -> :idle
    end
  end

  defp stage_level("triage", assigns) do
    cond do
      is_map(assigns.last_triage) and Map.get(assigns.last_triage, "rule_engine_overrode") == true -> :critical
      is_map(assigns.last_triage) -> :active
      assigns.last_triage == :pending -> :active
      true -> :idle
    end
  end

  defp stage_level("worm", assigns) do
    if assigns.worm_locked, do: :critical, else: :idle
  end

  defp stage_level("veeam", assigns) do
    case assigns.veeam_lock_state do
      "COMPLIANCE_LOCK" -> :critical
      "IMMUTABLE"       -> :active
      _                 -> :idle
    end
  end

  defp stage_level("unlock", assigns) do
    case assigns.unlock_state do
      "GRANTED"    -> :active
      "COLLECTING" -> :active
      _            -> :idle
    end
  end

  defp stage_level(_, _), do: :idle

  # ---------------------------------------------------------------------------
  # Framework reference data (static)
  # ---------------------------------------------------------------------------

  defp d3fend_mappings do
    [
      {"OMIDAX Layer 1", "D3-NTA",  "Network Traffic Analysis — entropy detection on live packet capture"},
      {"OMIDAX Layer 2", "D3-NTF",  "Network Traffic Filtering — rule engine blocks anomalous flows"},
      {"OMIDAX Layer 3", "D3-IAA",  "Identifier Activity Analysis — AI triage pre-classification (Step 18)"},
      {"OMIDAX Layer 4", "D3-CH",   "Credential Hardening — zero-trust short-lived scoped tokens (Step 8)"},
      {"DIBANET Layer 1","D3-DE",   "Decoy Environment — sandbox mirror surface for attacker containment"},
      {"DIBANET Layer 2","D3-DF",   "Decoy File — credential, data-valuation, lateral-movement poisoning"},
      {"DIBANET Layer 3","D3-CR",   "Connection Rerouting — silent redirect into lateral-movement subtree"},
      {"DIBANET Layer 4","D3-IAA",  "Identifier Activity Analysis — attribution report with ATT&CK mapping"},
    ]
  end

  defp nist_zta_mappings do
    [
      {"Identity",    "Continuous verification of every request — no implicit trust",          "Step 8 zero-trust tokens"},
      {"Device",      "Entropy-based anomaly detection on device traffic signatures",           "Step 5 Npcap sensor"},
      {"Network",     "Micro-segmentation via sandbox isolation; real firewall rules (Step 16)","Step 9 sandbox + Step 16"},
      {"Application", "Deterministic rule engine — explicit, fully enumerable policy",          "Step 7 rule engine"},
      {"Data",        "WORM + versioning: data is never overwritten, only locked or versioned", "Steps 2+3 version/WORM"},
    ]
  end

  defp csf_mappings do
    [
      {"Identify",  "csf-identify",  ["Asset inventory via sandbox file-manager", "Threat modelling via ATT&CK mapping"]},
      {"Protect",   "csf-protect",   ["Zero-trust tokens (Step 8)", "WORM lockdown (Step 3)", "ClamAV AV scanning (Step 14)"]},
      {"Detect",    "csf-detect",    ["Npcap entropy sensor (Step 5)", "Chaos detector K score (Step 12)", "Rule engine RULE-01..05 (Step 7)"]},
      {"Respond",   "csf-respond",   ["Active response throttling (Step 11)", "Decoy + poisoning (Step 10)", "Real firewall block (Step 16)"]},
      {"Recover",   "csf-recover",   ["Versioning rollback (Step 2)", "Attribution report (Step 13)", "12-eye WORM unlock (Step 17)"]},
    ]
  end

  defp kill_chain_stages do
    [
      {1, "Reconnaissance",   false, ""},
      {2, "Weaponization",    false, ""},
      {3, "Delivery",         true,  "ClamAV scanning (Step 14) intercepts malicious payload at delivery"},
      {4, "Exploitation",     true,  "Entropy + chaos detection (Steps 5,12) flags anomalous execution patterns"},
      {5, "Installation",     true,  "Credential poisoning (Step 10) serves fake credentials to implant"},
      {6, "C2",               true,  "Active response (Step 11) throttles and honeypots C2 communications"},
      {7, "Actions on Obj.", true,  "Sandbox containment + WORM lock (Steps 9,3) prevents data exfiltration"},
    ]
  end

  # ---------------------------------------------------------------------------
  # Demo agents — 50 AI agent personas for the grid
  # ---------------------------------------------------------------------------

  defp demo_agents do
    [
      %{"name" => "sentinel_alpha", "emoji" => "🛡️", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Primary network perimeter guardian. Monitors all ingress/egress traffic for anomalous patterns.", "tasks_completed" => 142, "uptime_s" => 86400},
      %{"name" => "sentinel_beta", "emoji" => "🛡️", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Secondary perimeter sentinel with deep packet inspection capabilities.", "tasks_completed" => 98, "uptime_s" => 86400},
      %{"name" => "threat_hunter_1", "emoji" => "🔍", "state" => "RUNNING", "model" => "granite3.1-moe:3b", "description" => "Proactive threat hunter — scans logs for IOCs and TTPs.", "tasks_completed" => 267, "uptime_s" => 43200},
      %{"name" => "threat_hunter_2", "emoji" => "🔍", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Proactive threat hunter — lateral movement detection specialist.", "tasks_completed" => 189, "uptime_s" => 43200},
      %{"name" => "malware_analyst", "emoji" => "🦠", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Static and dynamic malware analysis. YARA rule generation.", "tasks_completed" => 45, "uptime_s" => 7200},
      %{"name" => "forensics_lead", "emoji" => "🔬", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Digital forensics — disk, memory, and network artifact analysis.", "tasks_completed" => 23, "uptime_s" => 3600},
      %{"name" => "incident_commander", "emoji" => "👨‍✈️", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Orchestrates incident response playbooks and stakeholder comms.", "tasks_completed" => 12, "uptime_s" => 1800},
      %{"name" => "ioc_curator", "emoji" => "📋", "state" => "RUNNING", "model" => "granite3.1-moe:3b", "description" => "Maintains threat intelligence IOC database with STIX/TAXII feeds.", "tasks_completed" => 512, "uptime_s" => 86400},
      %{"name" => "sigint_analyst", "emoji" => "📡", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Signals intelligence — metadata analysis and traffic correlation.", "tasks_completed" => 89, "uptime_s" => 21600},
      %{"name" => "vuln_scanner", "emoji" => "🔧", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Continuous vulnerability scanning and CVSS scoring.", "tasks_completed" => 334, "uptime_s" => 86400},
      %{"name" => "patch_advisor", "emoji" => "🩹", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Recommends and validates patch deployment strategies.", "tasks_completed" => 156, "uptime_s" => 86400},
      %{"name" => "compliance_auditor", "emoji" => "📜", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "NIST 800-53, ISO 27001, and PCI-DSS compliance validation.", "tasks_completed" => 78, "uptime_s" => 43200},
      %{"name" => "soc_analyst_l1", "emoji" => "👁️", "state" => "RUNNING", "model" => "granite3.1-moe:3b", "description" => "Tier-1 SOC analyst — alert triage and initial classification.", "tasks_completed" => 1024, "uptime_s" => 86400},
      %{"name" => "soc_analyst_l2", "emoji" => "👁️", "state" => "RUNNING", "model" => "granite3.1-dense:8b", "description" => "Tier-2 SOC analyst — deep dive investigations and escalation.", "tasks_completed" => 567, "uptime_s" => 86400},
      %{"name" => "soc_analyst_l3", "emoji" => "👁️", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Tier-3 SOC analyst — advanced persistent threat hunting.", "tasks_completed" => 234, "uptime_s" => 86400},
      %{"name" => "deception_engineer", "emoji" => "🎭", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Designs and deploys honeypots, honeytokens, and decoy assets.", "tasks_completed" => 45, "uptime_s" => 7200},
      %{"name" => "behavioral_ai", "emoji" => "🧠", "state" => "RUNNING", "model" => "granite3.1-dense:8b", "description" => "UEBA — user and entity behavioral anomaly detection.", "tasks_completed" => 890, "uptime_s" => 86400},
      %{"name" => "crypto_guardian", "emoji" => "🔐", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Cryptographic health monitoring — key rotation, cipher suites.", "tasks_completed" => 67, "uptime_s" => 43200},
      %{"name" => "dlp_sentinel", "emoji" => "🚫", "state" => "RUNNING", "model" => "granite3.1-moe:3b", "description" => "Data loss prevention — egress monitoring and classification.", "tasks_completed" => 445, "uptime_s" => 86400},
      %{"name" => "cloud_sec_ops", "emoji" => "☁️", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Cloud security posture management — CSPM and misconfig detection.", "tasks_completed" => 123, "uptime_s" => 21600},
      %{"name" => "container_guard", "emoji" => "🐳", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Container and Kubernetes security — image scanning, runtime policies.", "tasks_completed" => 89, "uptime_s" => 21600},
      %{"name" => "api_sentinel", "emoji" => "🔌", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "API security gateway — rate limiting, auth validation, OWASP Top 10.", "tasks_completed" => 234, "uptime_s" => 43200},
      %{"name" => "iam_overseer", "emoji" => "🆔", "state" => "RUNNING", "model" => "granite3.1-dense:8b", "description" => "Identity and access management — privileged account monitoring.", "tasks_completed" => 567, "uptime_s" => 86400},
      %{"name" => "zero_trust_engine", "emoji" => "🎯", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Zero trust architecture enforcement — continuous verification.", "tasks_completed" => 78, "uptime_s" => 21600},
      %{"name" => "siem_correlator", "emoji" => "📊", "state" => "RUNNING", "model" => "granite3.1-moe:3b", "description" => "SIEM rule engine — multi-source event correlation and enrichment.", "tasks_completed" => 1024, "uptime_s" => 86400},
      %{"name" => "edr_responder", "emoji" => "💻", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Endpoint detection and response — automated isolation and remediation.", "tasks_completed" => 345, "uptime_s" => 43200},
      %{"name" => "xdr_orchestrator", "emoji" => "🌐", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Extended detection and response — cross-layer correlation.", "tasks_completed" => 156, "uptime_s" => 21600},
      %{"name" => "network_forensics", "emoji" => "🕸️", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Network traffic analysis — PCAP reconstruction and flow analysis.", "tasks_completed" => 67, "uptime_s" => 7200},
      %{"name" => "wireless_guardian", "emoji" => "📶", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Wireless network security — rogue AP detection and spectrum analysis.", "tasks_completed" => 89, "uptime_s" => 21600},
      %{"name" => "iot_sentinel", "emoji" => "📟", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "IoT device security — firmware analysis and anomaly detection.", "tasks_completed" => 123, "uptime_s" => 43200},
      %{"name" => "ot_guardian", "emoji" => "🏭", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Operational technology — ICS/SCADA security monitoring.", "tasks_completed" => 34, "uptime_s" => 7200},
      %{"name" => "supply_chain_guard", "emoji" => "📦", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Software supply chain — SBOM validation and dependency scanning.", "tasks_completed" => 78, "uptime_s" => 21600},
      %{"name" => "red_team_lead", "emoji" => "🎩", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Adversary simulation — red team exercise planning and execution.", "tasks_completed" => 23, "uptime_s" => 3600},
      %{"name" => "blue_team_lead", "emoji" => "🛡️", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Defense optimization — purple team collaboration and gap analysis.", "tasks_completed" => 45, "uptime_s" => 7200},
      %{"name" => "phishing_defender", "emoji" => "🎣", "state" => "RUNNING", "model" => "granite3.1-moe:3b", "description" => "Email security — phishing detection, sandbox detonation, user training.", "tasks_completed" => 2048, "uptime_s" => 86400},
      %{"name" => "ransomware_shield", "emoji" => "🛡️", "state" => "RUNNING", "model" => "granite3.1-dense:8b", "description" => "Ransomware-specific protection — behavioral indicators and canary files.", "tasks_completed" => 512, "uptime_s" => 86400},
      %{"name" => "insider_threat", "emoji" => "🕵️", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Insider threat detection — behavioral baselines and anomaly scoring.", "tasks_completed" => 167, "uptime_s" => 43200},
      %{"name" => "fraud_detector", "emoji" => "💳", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Financial fraud — transaction pattern analysis and alerting.", "tasks_completed" => 234, "uptime_s" => 43200},
      %{"name" => "botnet_tracker", "emoji" => "🤖", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Botnet C2 tracking — DGA detection and sinkhole coordination.", "tasks_completed" => 89, "uptime_s" => 21600},
      %{"name" => "darkweb_monitor", "emoji" => "🌑", "state" => "RUNNING", "model" => "granite3.1-dense:8b", "description" => "Dark web intelligence — credential leaks, threat actor forums.", "tasks_completed" => 445, "uptime_s" => 86400},
      %{"name" => "geoint_analyst", "emoji" => "🌍", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Geospatial threat intelligence — attack origin and campaign mapping.", "tasks_completed" => 67, "uptime_s" => 7200},
      %{"name" => "attribution_engine", "emoji" => "🎯", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Threat actor attribution — TTP correlation and MITRE mapping.", "tasks_completed" => 34, "uptime_s" => 3600},
      %{"name" => "auto_remediator", "emoji" => "⚡", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "SOAR playbooks — automated containment and eradication.", "tasks_completed" => 234, "uptime_s" => 43200},
      %{"name" => "ticket_router", "emoji" => "🎫", "state" => "RUNNING", "model" => "granite3.1-moe:3b", "description" => "Case management — auto-triage, SLA tracking, and escalation.", "tasks_completed" => 1024, "uptime_s" => 86400},
      %{"name" => "report_generator", "emoji" => "📑", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Executive and technical reporting — metrics, trends, and KPIs.", "tasks_completed" => 156, "uptime_s" => 21600},
      %{"name" => "war_room_ai", "emoji" => "🏢", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Crisis management — scenario planning and resource allocation.", "tasks_completed" => 12, "uptime_s" => 1800},
      %{"name" => "metrics_engineer", "emoji" => "📈", "state" => "RUNNING", "model" => "granite3.1-moe:3b", "description" => "Security metrics — MTTR, MTTD, coverage gaps, and maturity scores.", "tasks_completed" => 789, "uptime_s" => 86400},
      %{"name" => "threat_intel_feed", "emoji" => "📰", "state" => "RUNNING", "model" => "granite3.1-moe:3b", "description" => "STIX/TAXII feed ingestion and indicator lifecycle management.", "tasks_completed" => 2048, "uptime_s" => 86400},
      %{"name" => "sandbox_analyst", "emoji" => "🔬", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Malware sandbox — dynamic analysis and IOC extraction.", "tasks_completed" => 67, "uptime_s" => 7200},
      %{"name" => "memory_forensics", "emoji" => "🧠", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Memory dump analysis — rootkit detection and process hollowing.", "tasks_completed" => 34, "uptime_s" => 3600},
      %{"name" => "disk_forensics", "emoji" => "💾", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Disk image forensics — file carving, timeline analysis, and hashing.", "tasks_completed" => 23, "uptime_s" => 3600},
      %{"name" => "mobile_sec_ops", "emoji" => "📱", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Mobile device security — MDM, app vetting, and sideload detection.", "tasks_completed" => 89, "uptime_s" => 21600},
      %{"name" => "web_app_firewall", "emoji" => "🧱", "state" => "RUNNING", "model" => "granite3.1-moe:3b", "description" => "WAF optimization — OWASP rules, bot mitigation, and DDoS protection.", "tasks_completed" => 512, "uptime_s" => 86400},
      %{"name" => "backup_guardian", "emoji" => "💾", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Backup integrity — immutability, air-gapping, and restore validation.", "tasks_completed" => 123, "uptime_s" => 43200},
      %{"name" => "dr_coordinator", "emoji" => "🏥", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Disaster recovery — failover testing, RTO/RPO validation, and runbooks.", "tasks_completed" => 45, "uptime_s" => 7200},
      %{"name" => "chaos_engineer", "emoji" => "🔥", "state" => "IDLE", "model" => "granite3.1-dense:8b", "description" => "Resilience testing — chaos engineering and failure injection.", "tasks_completed" => 23, "uptime_s" => 3600},
      %{"name" => "entropy_guardian", "emoji" => "🌊", "state" => "RUNNING", "model" => "granite3.1-dense:8b", "description" => "Network entropy analysis — anomaly detection via Shannon entropy.", "tasks_completed" => 890, "uptime_s" => 86400},
      %{"name" => "policy_enforcer", "emoji" => "📜", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Security policy automation — GPO, CASB, and firewall rule validation.", "tasks_completed" => 234, "uptime_s" => 43200},
      %{"name" => "awareness_trainer", "emoji" => "🎓", "state" => "IDLE", "model" => "granite3.1-moe:3b", "description" => "Security awareness — simulated phishing, training modules, and metrics.", "tasks_completed" => 156, "uptime_s" => 21600}
    ]
  end
end
