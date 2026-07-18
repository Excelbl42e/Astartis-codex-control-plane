defmodule AstartisWebWeb.PageController do
  use AstartisWebWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
