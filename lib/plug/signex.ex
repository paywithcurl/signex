defmodule Plug.SignEx do
  import Plug.Conn

  def init(opts) do
    opts
  end

  def call(conn, public_key) do
    case Plug.Conn.get_req_header(conn, "authorization") |> List.first do
      "Signature " <> signature ->
        {:ok, parameters} = SignEx.HTTP.parse_parameters(signature)
        case SignEx.verify_signing(conn.req_headers, parameters, public_key) do
          true ->
            conn
        # TODO signature doesn't checkout
        end
      _ ->
        conn
        |> halt
    end
    digest = Plug.Conn.get_req_header(conn, "digest") |> List.first
    case digest do
      nil ->
        conn
        |> halt
      digest ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      SignEx.HTTP.check_digest_header(digest, body)
      conn
    end
  end
end
