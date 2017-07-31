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
      query_string: "",
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

  test "successful validation", %{keypair: keypair} do
    request = %{
      method: :POST,
      path: "/some/path",
      query_string: "",
      headers: [{"content-type", "application/json"}],
      body: Poison.encode!(%{some: "content"})
    }
    signed_request = SignEx.HTTP.sign(request, keypair)
    assert {:ok, ^signed_request} = SignEx.HTTP.verify(signed_request, keypair.public_key)
  end

  test "Missing authorization", %{keypair: keypair} do
    request = %{
      method: :POST,
      path: "/some/path",
      query_string: "",
      headers: [{"content-type", "application/json"}],
      body: Poison.encode!(%{some: "content"})
    }
    signed_request = %{headers: headers} = SignEx.HTTP.sign(request, keypair)
    signed_request = %{signed_request | headers: :proplists.delete("authorization", headers)}
    assert {:error, :missing_authorization_header} = SignEx.HTTP.verify(signed_request, keypair.public_key)
  end

  test "unexpected authorization type", %{keypair: keypair} do
    request = %{
      method: :POST,
      path: "/some/path",
      query_string: "",
      headers: [{"content-type", "application/json"}],
      body: Poison.encode!(%{some: "content"})
    }
    signed_request = %{headers: headers} = SignEx.HTTP.sign(request, keypair)
    headers = :proplists.delete("authorization", headers)
    headers = headers ++ [{"authorization", "Basic password"}]
    signed_request = %{signed_request | headers: headers}
    assert {:error, {:unrecognised_authorization, _}} = SignEx.HTTP.verify(signed_request, keypair.public_key)
  end

  test "incorrectly serialized signature params", %{keypair: keypair} do
    request = %{
      method: :POST,
      path: "/some/path",
      query_string: "",
      headers: [{"content-type", "application/json"}],
      body: Poison.encode!(%{some: "content"})
    }
    signed_request = %{headers: headers} = SignEx.HTTP.sign(request, keypair)
    headers = :proplists.delete("authorization", headers)
    headers = headers ++ [{"authorization", "Signature password"}]
    signed_request = %{signed_request | headers: headers}
    assert {:error, {:unparsable_signature_parameters, _}} = SignEx.HTTP.verify(signed_request, keypair.public_key)
  end

  test "key not available", %{keypair: keypair} do
    request = %{
      method: :POST,
      path: "/some/path",
      query_string: "",
      headers: [{"content-type", "application/json"}],
      body: Poison.encode!(%{some: "content"})
    }
    signed_request = SignEx.HTTP.sign(request, keypair)
    assert {:error, {:key_not_found, _}} = SignEx.HTTP.verify(signed_request, fn(id) -> {:error, {:key_not_found, id}} end)
  end

end
