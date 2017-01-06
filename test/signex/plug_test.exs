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
    headers = [{"host", "example.com"}]

    digest_header = SignEx.generate_digest(body)
    headers = headers ++ [{"digest", digest_header}]

    authorization =  SignEx.HTTP.signature_header_for(headers, %{
      private_key: private_key,
      public_key: public_key
    })

    conn = conn(:post, "/foo/bar", body)
    |> put_req_header("host", "example.com")
    |> put_req_header("digest", digest_header)
    |> put_req_header("authorization", authorization)


    conn = MyApp.call(conn, public_key)

    assert conn.state == :sent
    assert conn.status == 200
  end

end
