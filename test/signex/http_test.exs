defmodule SignEx.HTTPTest do
  use ExUnit.Case

  setup do
    private_key = File.read!(Path.expand("../../keys/private_key.pem", __ENV__.file))
    public_key = File.read!(Path.expand("../../keys/public_key.pem", __ENV__.file))
    {:ok,
      private_key: private_key,
      public_key: public_key,
      keypair: %{private_key: private_key, public_key: public_key}
    }
  end

  test "sign a valid HTTP request with body", %{keypair: keypair} do
    request = %{
      method: :POST,
      path: "/some/path",
      query_string: "a=a&b=b",
      headers: [{"content-type", "application/json"}],
      body: Poison.encode!(%{some: "content"})
    }
    signed_request = SignEx.HTTP.sign(request, keypair)
    assert "Signature " <> signature_string = :proplists.get_value("authorization", signed_request.headers)
    assert {:ok, %{headers: ["(request-target)", "content-type", "digest"]}} = SignEx.Parameters.parse(signature_string)
    assert true == SignEx.HTTP.verified?(signed_request, keypair.public_key)
  end

  test "look up public key from the parameters key_id", %{keypair: keypair} do
    request = %{
      method: :POST,
      path: "/some/path",
      query_string: "a=a&b=b",
      headers: [{"content-type", "application/json"}],
      body: Poison.encode!(%{some: "content"})
    }
    signed_request = SignEx.HTTP.sign(request, keypair)
    assert "Signature " <> signature_string = :proplists.get_value("authorization", signed_request.headers)
    assert {:ok, %{headers: ["(request-target)", "content-type", "digest"]}} = SignEx.Parameters.parse(signature_string)
    assert true == SignEx.HTTP.verified?(signed_request, fn
      (_key_id) -> {:ok, keypair.public_key}
    end)
  end
end
