# move signature into headers
defmodule SignEx.Message do
  defstruct [
    signature: %{
      key_id: nil,
      algorithm: nil,
      headers: nil,

    }
  ]
end

# if following the standard then joining fields is done with ": "
# Agnostic message object would have to do the same to get the same result.
# This would tie the message object to the http specifcation
# Only problematic is a secondary standard were to ever arise, a non issue as even the first standard is new
# Alternatives would be to resign messages by public api to pass them on.
# Or to not that the message was originally sent over HTTP
# Core problem is that signing works best for single transport journey.

# Suggest putting the signature within the headers of the message object, or taking the digest out
# Aim to keep message object extensible

# only signed by publisher internally

defmodule Plug.SignEx do
  import Plug.Conn

  def init(opts) do
    opts
  end

  def call(conn, public_key) do
    case Plug.Conn.get_req_header(conn, "authorization") |> List.first do
      "Signature " <> signature ->
        {:ok, %{signature: signature, headers: headers}} = SignEx.Parameters.parse(signature)
        {:ok, signature} = Base.decode64(signature)
        message = headers
        |> Enum.map(fn(host) -> List.keyfind(conn.req_headers, host, 0) end)
        |> SignEx.HTTP.compose_signing_string

        checked = :public_key.verify(message, :sha512, signature, SignEx.Helper.decode_key(public_key))
        case checked do
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
