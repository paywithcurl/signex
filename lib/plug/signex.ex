defmodule Plug.SignEx do
  import Plug.Conn

  def init(opts) do
    opts
  end

  def call(conn, public_key) do
    case Plug.Conn.get_req_header(conn, "authorization") |> List.first do
      "Signature " <> signature ->
        {:ok, parameters} = SignEx.HTTP.parse_parameters(signature)
        case SignEx.signature_valid?(conn.req_headers, parameters, public_key) do
          true ->
            conn
        # TODO signature doesn't checkout
        end
      _ ->
        conn
        |> halt
    end
    digest = Plug.Conn.get_req_header(conn, "digest") |> List.first
    {:ok, body, conn} = Plug.Conn.read_body(conn)
    case digest do
      nil ->
        conn
        |> halt
      digest ->
        SignEx.digest_valid?(body, digest)
        conn
    end
  end
end
