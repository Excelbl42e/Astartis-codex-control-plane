defmodule AstartisWeb.Core.AstartisState do
  @moduledoc """
  ETS-backed in-memory cache for the latest C++ bridge snapshot.

  Freshly-mounted LiveView sockets read this to get immediate state
  without waiting for the next 500ms tick from the bridge.

  Reads go directly against ETS (no GenServer round-trip needed).
  Writes go through a GenServer cast to serialise concurrent updates.
  """

  use GenServer

  @table :astartis_state

  @default_state %{
    "threat_tier"       => 0,
    "threat_tier_name"  => "LOW",
    "threat_transitions"=> 0,
    "worm_locked"       => false,
    "worm_reason"       => "",
    "worm_lock_count"   => 0,
    "chain_length"      => 0,
    "chain_valid"       => true,
    "chain_head"        => "",
    "chaos_K"           => 0.0,
    "chaos_anomalous"   => false,
    "chaos_windows"     => 0,
    "chaos_history"     => [],
    "rule_fires"        => 0,
    "worm_triggers"     => 0,
    "decoy_events"      => 0,
    "sandbox_entries"   => [],
    "sandbox_root"      => "",
    # Pass 2 fields (populated when attribution_report event arrives)
    "attribution_techniques" => [],
    "kill_chain_stages"      => [],
    "active_response_events" => []
  }

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Update the snapshot (called by AstartisPort on every tick)."
  def put(data) when is_map(data) do
    if GenServer.whereis(__MODULE__) do
      GenServer.cast(__MODULE__, {:put, data})
    end
  end

  @doc "Read the current snapshot directly from ETS. Returns the default if not yet set."
  def get do
    case :ets.lookup(@table, :snapshot) do
      [{:snapshot, data}] -> data
      []                  -> @default_state
    end
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@table, [:set, :public, :named_table, {:read_concurrency, true}])
    :ets.insert(@table, {:snapshot, @default_state})
    {:ok, %{}}
  end

  @impl true
  def handle_cast({:put, data}, state) do
    # Merge incoming data with existing state (don't lose fields the bridge
    # doesn't send on every message, e.g. attribution_techniques from Pass 2)
    current = get()
    merged  = Map.merge(current, data)
    :ets.insert(@table, {:snapshot, merged})
    {:noreply, state}
  end
end
