defmodule Plug.SignEx do
  import Plug.Conn

  def init(opts) do
    opts
  end

  def call(conn, public_key) do
    case Plug.Conn.get_req_header(conn, "authorization") |> List.first do
      "Signature " <> signature ->
        signature

        %{"signature" => signature, "headers" => headers} =
          ~r/^.*headers="(?<headers>[^"]*)",signature="(?<signature>[^"]*)"$/ |> Regex.named_captures(signature)
        {:ok, signature} = Base.decode64(signature)
        message = String.split(headers, " ")
        |> Enum.map(fn(host) -> List.keyfind(conn.req_headers, host, 0) end)
        |> Enum.map(fn({k, v}) -> "#{k}: #{v}" end)
        |> Enum.join("\r\n")
        |> IO.inspect


        checked = :public_key.verify(message, :sha512, signature, SignEx.Helper.decode_key(public_key))
        case checked do
          true ->
            conn
        # TODO signature doesn't check
        end
      _ ->
        IO.inspect("nope")
    end
    digest = Plug.Conn.get_req_header(conn, "digest") |> List.first
    case digest do
      nil ->
        conn
        |> halt
      digest ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      {:ok, digest} = digest |> Base.decode64 # Check if base64 specified in rfc
      SignEx.HTTP.check_digest_header(digest, body)
      conn
    end
  end
end
