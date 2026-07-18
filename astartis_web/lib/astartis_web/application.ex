defmodule AstartisWeb.Application do
  # See https://elixir.hexdocs.pm/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    core_children = [
      AstartisWebWeb.Telemetry,
      {DNSCluster, query: Application.get_env(:astartis_web, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: AstartisWeb.PubSub},
      # AstartisState must start before AstartisPort so the ETS table exists
      # when the first tick arrives.
      AstartisWeb.Core.AstartisState
    ]

    bridge_children =
      if Application.get_env(:astartis_web, :start_bridge, true) do
        [
          # AstartisPort owns the Port to astartis_bridge.exe.
          # restart: :permanent so the supervisor restarts it if the bridge crashes.
          %{
            id: AstartisWeb.Core.AstartisPort,
            start: {AstartisWeb.Core.AstartisPort, :start_link, [[]]},
            restart: :permanent,
            shutdown: 5_000,
            type: :worker
          }
        ]
      else
        []
      end

    children = core_children ++ bridge_children ++ [
      AstartisWebWeb.Endpoint
    ]

    # See https://elixir.hexdocs.pm/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: AstartisWeb.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    AstartisWebWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
