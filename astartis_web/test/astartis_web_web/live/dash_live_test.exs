defmodule AstartisWebWeb.DashLiveTest do
  use AstartisWebWeb.ConnCase, async: true

  import Phoenix.LiveViewTest

  # The bridge is not started in the test environment, so these tests stand in
  # for it by sending the same {:telemetry, event, data} messages AstartisPort
  # broadcasts when the native bridge emits a line.

  @audit_events [
    {"entry_6f1c2a9b0d3e4f51", "sandbox_populated", 1_792_054_710_100},
    {"entry_9a7b3c5d1e2f4a60", "worm_trigger", 1_792_054_710_250},
    {"entry_0c4d8e2f6a1b3c79", "sandbox_entry_locked", 1_792_054_710_484}
  ]

  # Shaped like the bridge's "audit_entries": hashed the way AuditChain does
  # (SHA-256 of entry_id, timestamp, event_type, payload, previous_hash) and
  # linked by previous_hash. The bridge leaves payloads out of the snapshot.
  defp audit_entries(first_index, events) do
    seed = sha256("entry #{first_index - 1}")

    {entries, _head} =
      events
      |> Enum.with_index(first_index)
      |> Enum.map_reduce(seed, fn {{entry_id, event_type, ts}, index}, previous_hash ->
        current_hash = sha256("#{entry_id}#{ts}#{event_type}payload-#{index}#{previous_hash}")

        entry = %{
          "index" => index,
          "entry_id" => entry_id,
          "event_type" => event_type,
          "timestamp" => ts,
          "previous_hash" => previous_hash,
          "current_hash" => current_hash
        }

        {entry, current_hash}
      end)

    entries
  end

  defp sha256(data), do: :crypto.hash(:sha256, data) |> Base.encode16(case: :lower)

  defp open_app(view, app) do
    view |> element(~s{.dock-item[phx-value-app="#{app}"]}) |> render_click()
  end

  defp bridge_event(view, event, data) do
    send(view.pid, {:telemetry, event, data})
    render(view)
  end

  describe "audit tab" do
    test "renders the entries the bridge reported", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/")
      entries = audit_entries(41, @audit_events)
      [first, second, last] = entries

      bridge_event(view, "snapshot", %{
        "chain_length" => 43,
        "chain_valid" => true,
        "chain_head" => String.slice(last["current_hash"], 0, 12),
        "audit_entries" => entries
      })

      html = open_app(view, "audit")
      assert html =~ "latest 3 of 43 entries"
      assert html =~ "all 43 hashes verified by the C++ bridge"
      refute has_element?(view, ~s{[data-testid="audit-empty"]})

      chain = view |> element(".chain-blocks") |> render()
      assert length(Regex.scan(~r/data-testid="audit-block"/, chain)) == 3

      for entry <- entries do
        assert chain =~ "##{entry["index"]}"
        assert chain =~ entry["event_type"]
        assert chain =~ String.slice(entry["current_hash"], 0, 12)
      end

      # The old placeholder cycled invented event names and "...abcdef" hashes.
      refute chain =~ "abcdef"
      refute chain =~ "packet_anomaly"

      detail =
        view
        |> element(~s{[data-testid="audit-block"][phx-value-id="#{second["entry_id"]}"]})
        |> render_click()

      assert detail =~ "Entry #42 — worm_trigger"
      assert detail =~ second["entry_id"]
      assert detail =~ "2026-10-15 08:58:30.250 UTC"
      # Full hashes, with the chain link to the previous entry visible.
      assert detail =~ first["current_hash"]
      assert detail =~ second["current_hash"]
      assert second["previous_hash"] == first["current_hash"]

      # Clicking the selected block again closes the detail panel.
      view
      |> element(~s{[data-testid="audit-block"][phx-value-id="#{second["entry_id"]}"]})
      |> render_click()

      refute has_element?(view, ~s{[data-testid="audit-entry-detail"]})
    end

    test "labels the empty states instead of drawing placeholder blocks", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/")

      open_app(view, "audit")

      assert view |> element(~s{[data-testid="audit-empty"]}) |> render() =~
               "No audit entries reported by the bridge yet"

      assert render(view) =~ "No entries to verify yet"

      # A bridge build that reports a chain length but no entry details.
      html = bridge_event(view, "tick", %{"chain_length" => 12, "chain_valid" => true})

      assert html =~ "The bridge reports 12 chain entries but sent no entry details"
      refute has_element?(view, ~s{[data-testid="audit-block"]})

      html = bridge_event(view, "tick", %{"chain_length" => 12, "chain_valid" => false})
      assert html =~ "found an entry whose hash does not match"
      refute html =~ "hashes verified by the C++ bridge"

      html = bridge_event(view, "tick", %{"chain_length" => 12, "chain_valid" => nil})
      assert html =~ "Chain integrity not reported by the bridge"
      refute html =~ "hashes verified by the C++ bridge"
    end
  end

  describe "agent fleet" do
    test "shows an explicit empty state when the bridge returns no agents", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/")

      open_app(view, "agents")

      assert view |> element(~s{[data-testid="agent-empty"]}) |> render() =~
               "Waiting for the native bridge to report the agent catalog."

      bridge_event(view, "agent_status_update", %{
        "agent_statuses" => [],
        "agent_queue_depth" => 0
      })

      empty = view |> element(~s{[data-testid="agent-empty"]}) |> render()
      assert empty =~ "The bridge returned no agents."
      refute has_element?(view, ".agent-node")
      # Names from the removed hardcoded demo roster.
      refute render(view) =~ "sentinel_alpha"
      refute render(view) =~ "threat_hunter_1"

      bridge_event(view, "agent_status_update", %{
        "agent_statuses" => [],
        "agent_queue_depth" => 0,
        "error" => "agent_controller_not_initialised"
      })

      assert view |> element(~s{[data-testid="agent-empty"]}) |> render() =~
               "The bridge returned no agents (agent_controller_not_initialised)."
    end

    test "renders exactly the agents the bridge reported", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/")

      bridge_event(view, "agent_status_update", %{
        "agent_statuses" => [
          %{
            "name" => "alert_triage",
            "category" => "soc",
            "state" => "IDLE",
            "tasks_completed" => 3,
            "tasks_failed" => 1
          }
        ],
        "agent_queue_depth" => 0
      })

      html = open_app(view, "agents")
      assert length(Regex.scan(~r/class="agent-node /, html)) == 1
      assert view |> element(".agent-node") |> render() =~ "alert_triage"
      refute has_element?(view, ~s{[data-testid="agent-empty"]})
    end
  end

  describe "AI triage" do
    test "rejects non-numeric and out-of-range scores without crashing", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/")
      open_app(view, "defense")

      for bad <- ["abc", "42abc", "4.5", "150", "-1", ""] do
        html =
          render_submit(view, "run_triage", %{"event_type" => "entropy_anomaly", "score" => bad})

        assert html =~ "Score must be a whole number from 0 to 100.",
               "accepted score #{inspect(bad)}"
      end

      assert Process.alive?(view.pid)

      html =
        view
        |> form(~s{form[phx-submit="run_triage"]}, %{
          "event_type" => "entropy_anomaly",
          "score" => "75"
        })
        |> render_submit()

      assert html =~ "Local AI triage in progress"
      refute has_element?(view, ~s{[data-testid="triage-error"]})
    end

    test "rejects a triage request that carries no form fields", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/")
      open_app(view, "pipeline")

      view |> element(~s{button[phx-click="run_triage"]}) |> render_click()

      assert Process.alive?(view.pid)
      assert open_app(view, "terminal") =~ "triage rejected"
    end
  end

  describe "sandbox lock" do
    @entry %{
      "rel_path" => "etc/nginx.conf",
      "type" => "file",
      "size_bytes" => 512,
      "version" => 1,
      "locked" => false,
      "last_modified" => 1_792_054_710_100
    }

    test "reports a lock only after the bridge confirms it", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/")
      bridge_event(view, "snapshot", %{"sandbox_entries" => [@entry]})

      open_app(view, "sandbox")

      view
      |> element(~s{[phx-click="sandbox_select"][phx-value-path="etc/nginx.conf"]})
      |> render_click()

      view |> element(~s{button[phx-click="sandbox_lock"]}) |> render_click()

      terminal = open_app(view, "terminal")
      assert terminal =~ "lock requested path=etc/nginx.conf"
      refute terminal =~ "locked path=etc/nginx.conf"

      bridge_event(view, "sandbox_lock_result", %{
        "path" => "etc/nginx.conf",
        "ok" => true,
        "error" => "",
        "entry" => %{@entry | "locked" => true}
      })

      assert open_app(view, "terminal") =~ "locked path=etc/nginx.conf"

      open_app(view, "sandbox")

      assert view |> element(~s{button[phx-click="sandbox_lock"][disabled]}) |> render() =~
               "Locked"
    end

    test "logs the bridge's rejection", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/")

      bridge_event(view, "sandbox_lock_result", %{
        "path" => "../outside",
        "ok" => false,
        "error" => "path outside sandbox root",
        "entry" => nil
      })

      terminal = open_app(view, "terminal")
      assert terminal =~ "lock rejected path=../outside error=path outside sandbox root"
      refute terminal =~ "locked path=../outside"
    end
  end
end
