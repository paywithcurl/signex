defmodule SignEx.Mixfile do
  use Mix.Project

  @version File.read!("VERSION") |> String.trim()

  def project do
    [
      app: :signex,
      version: @version,
      elixir: "~> 1.3",
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps()
    ]
  end

  def application do
    [applications: [:logger, :public_key]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/keys"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:poison, "~> 2.0 or ~> 4.0"},
      {:plug, "~> 1.0"},
      {:dialyxir, "~> 1.0.0-rc.3", only: [:test, :dev], runtime: false}
    ]
  end
end
