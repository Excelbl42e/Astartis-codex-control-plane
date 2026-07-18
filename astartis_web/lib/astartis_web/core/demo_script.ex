defmodule AstartisWeb.Core.DemoScript do
  @moduledoc """
  Scripted demo sequence for Pass 1 testing.

  Sends a series of commands to the bridge that exercises all four
  Pass 1 dashboard panels:
    - Threat tier badge: LOW → MEDIUM → HIGH → CRITICAL
    - Chaos K chart: logistic-map series (r=4) → K rises above 0.7
    - WORM status: locks at the end of the sequence
    - Sandbox file-manager: files show as locked after WORM fires

  Call run/0 from IEx or from the "Run Demo" button in the dashboard.
  """

  alias AstartisWeb.Core.AstartisPort

  def run do
    unless AstartisPort.running?() do
      {:error, :bridge_not_running}
    else
      # Delegate to the bridge's own run_demo handler so the entire
      # scripted sequence runs in C++ (consistent state, no timing gaps)
      AstartisPort.send_command(%{"cmd" => "run_demo"})
      :ok
    end
  end

  @doc "Trigger WORM lockdown only."
  def trigger_worm(reason \\ "manual") do
    AstartisPort.send_command(%{"cmd" => "worm_trigger", "args" => %{"reason" => reason}})
  end

  @doc "Unlock WORM."
  def unlock_worm(authority \\ "demo") do
    AstartisPort.send_command(%{"cmd" => "worm_unlock", "args" => %{"authority" => authority}})
  end

  @doc "Fetch attribution report for the demo session (used by Pass 2 ATT&CK tab)."
  def get_attribution(session \\ "demo-atk") do
    AstartisPort.send_command(%{"cmd" => "get_attribution", "args" => %{"session" => session}})
  end

  @doc "Send a single threat signal."
  def observe_signal(score, source \\ "demo") do
    AstartisPort.send_command(%{
      "cmd"  => "observe_signal",
      "args" => %{"score" => score, "source" => source}
    })
  end

  @doc "Push chaos samples (list of floats)."
  def push_chaos(values) when is_list(values) do
    Enum.each(values, fn v ->
      AstartisPort.send_command(%{
        "cmd"  => "push_chaos",
        "args" => %{"value" => v, "synthetic" => true}
      })
    end)
  end

  @doc "Generate logistic-map series of length n at r=4 starting from x0."
  def logistic_map(n, x0 \\ 0.5) do
    Enum.scan(1..n, x0, fn _i, x -> 4.0 * x * (1.0 - x) end)
  end
end
