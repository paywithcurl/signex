defmodule MyApp do
  use Plug.Builder

  plug Plug.SignEx, File.read!(Path.expand("../../keys/public_key.pem", __ENV__.file))
  plug :ok

  def ok(conn, _) do
    conn
    |> send_resp(200, "hello")
  end

end

defmodule SignEx.PlugTest do
  use ExUnit.Case
  use Plug.Test

  setup do
    {:ok,
      private_key: File.read!(Path.expand("../../keys/private_key.pem", __ENV__.file)),
      public_key: File.read!(Path.expand("../../keys/public_key.pem", __ENV__.file))
    }
  end

  test "failing to send digest terminates request" do
    body = "Hello"
    conn = conn(:post, "/foo/bar", body)
    |> put_req_header("host", "example.com")

    conn = MyApp.call(conn, nil)

    # TODO send the correct response AND halt
    assert conn.state == :unset
  end

  test "verifying request with body and digest", %{public_key: public_key, private_key: private_key} do
    body = "Hello"
    digest = SignEx.HTTP.digest_header_for(body) |> Base.encode64

    {:ok, signature_content} = SignEx.HTTP.signature_string([
      {"host", "example.com"},
      {"digest", digest}
    ], headers: [:host, :digest])

    signature = SignEx.Signer.sign_message(signature_content, private_key)
    :public_key.verify(signature_content, :sha512, signature, SignEx.Helper.decode_key(public_key))
    "signature" <> "auth params"
    key_id = "myid"
    authorization = "Signature key_id=\"#{key_id}\",algorithm=\"rsa-sha256\",headers=\"host digest\",signature=\"#{Base.encode64(signature)}\""

    conn = conn(:post, "/foo/bar", body)
    |> put_req_header("host", "example.com")
    |> put_req_header("digest", digest)
    |> put_req_header("authorization", authorization)


    conn = MyApp.call(conn, public_key)

    assert conn.state == :sent
    assert conn.status == 200
  end

end
