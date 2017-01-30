defmodule Mel.InvoiceApprovedConsumerTest do
  use ExUnit.Case, async: true

  test "signing fails when body not a binary" do
    assert_raise FunctionClauseError, fn() ->
      SignEx.sign(5, %{}, %{public_key: "public", private_key: "private"})
    end
  end

  test "signing fails when keys not provided" do
    assert_raise FunctionClauseError, fn() ->
      SignEx.sign("body", %{}, %{public_key: nil, private_key: nil})
    end
  end

  test "fails to sign if a signature already present" do
    {:error, reason} = SignEx.sign("hi", %{"signature" => "my-signature"}, %{public_key: "public", private_key: "private"})
  end

  describe "#sign with rsa keys" do
    setup do
      private_key = File.read!(Path.expand("../keys/private_key.pem", __ENV__.file))
      public_key = File.read!(Path.expand("../keys/public_key.pem", __ENV__.file))
      {:ok,
        private_key: private_key,
        public_key: public_key,
        keypair: %{private_key: private_key, public_key: public_key}
      }
    end


    test "verify message with body contents", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      assert true == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "verify message with empty body", %{keypair: keypair} do
      content = ""
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      assert true == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "tampering with the content compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      content = content <> "nefarious"
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "tampering with any metadata compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = %{metadata | "some-content" => "new-value"}
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "deleting any metadata compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = Map.delete(metadata, "some-content")
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "tampering with the digest compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = %{metadata | "digest" => "SHA-256=some other string"}
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "deleting the digest compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = Map.delete(metadata, "digest")
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end


    test "modifiying the signature compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      signature = %{signature | signature: signature.signature <> "extra"}
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "metadata must have a string representation", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"some-content" => {:not_a_string}}
      assert_raise Protocol.UndefinedError, fn() ->
        {:ok, {_metadata, _signature}} = SignEx.sign(content, metadata, keypair)
      end
    end
  end

  describe "#sign with ec keys" do
    setup do
      private_key = File.read!(Path.expand("../keys/ec_private_key.pem", __ENV__.file))
      public_key = File.read!(Path.expand("../keys/ec_public_key.pem", __ENV__.file))
      {:ok,
        keypair: %{private_key: private_key, public_key: public_key}
      }
    end

    test "verify message with body contents", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      assert true == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "verify message with empty body", %{keypair: keypair} do
      content = ""
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      assert true == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "deleting the digest compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = Map.delete(metadata, "digest")
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "tampering with the content compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      content = content <> "nefarious"
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "tampering with any metadata compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = %{metadata | "some-content" => "new-value"}
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "deleting any metadata compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = Map.delete(metadata, "some-content")
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end


    test "modifiying the signature compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      signature = %{signature | signature: signature.signature <> "extra"}
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

  end
end
