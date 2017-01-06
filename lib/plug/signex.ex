defmodule Plug.SignEx do
  import Plug.Conn

  def init(opts) do
    opts
  end

  def call(conn, public_key) do
    case Plug.Conn.get_req_header(conn, "authorization") |> List.first do
      "Signature " <> signature_string ->
        {:ok, signature} = SignEx.HTTP.parse_parameters(signature_string)
        digest = (Plug.Conn.get_req_header(conn, "digest") |> List.first) || ""
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        headers = conn.req_headers |> Enum.into(%{})
        if SignEx.verified?(body, headers, signature, public_key) do
            conn
        else
          conn
          |> halt
        end
      _ ->
        conn
        |> halt
    end
  end
end
