defmodule Mel.InvoiceApprovedConsumerTest do
  use ExUnit.Case, async: true

  test "checking digest for some content" do
    header = SignEx.generate_digest("hello")
    assert SignEx.digest_valid?("hello", header)
    refute SignEx.digest_valid?("other", header)
  end

  test "checking digest for no content" do
    header = SignEx.generate_digest("")
    assert SignEx.digest_valid?("", header)
    refute SignEx.digest_valid?("other", header)
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
      metadata = %{"my-key" => "my-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      assert SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "verify message with empty body", %{keypair: keypair} do
      content = ""
      metadata = %{"my-key" => "my-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      assert SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "deleting the digest compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"my-key" => "my-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = Map.delete(metadata, "digest")
      refute SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "tampering with the digest compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"my-key" => "my-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      content = content <> "nefarious"
      refute SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "tampering with any metadata compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"my-key" => "my-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = %{metadata | "my-key" => "new-value"}
      refute SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "deleting any metadata compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"my-key" => "my-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = Map.delete(metadata, "my-key")
      refute SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    # Other cases
    # Changing the signature
    # Changing the algorithm -> will pass at the moment as algorithm hardcoded

    test "metadata must have a string representation", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"my-key" => {:not_a_string}}
      assert_raise Protocol.UndefinedError, fn() ->
        {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
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
      metadata = %{"my-key" => "my-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      assert SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "verify message with empty body", %{keypair: keypair} do
      content = ""
      metadata = %{"my-key" => "my-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      assert SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "deleting the digest compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"my-key" => "my-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = Map.delete(metadata, "digest")
      refute SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "tampering with the digest compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"my-key" => "my-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      content = content <> "nefarious"
      refute SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "tampering with any metadata compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"my-key" => "my-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = %{metadata | "my-key" => "new-value"}
      refute SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "deleting any metadata compromises the message", %{keypair: keypair} do
      content = "My exiting message!!!"
      metadata = %{"my-key" => "my-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = Map.delete(metadata, "my-key")
      refute SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    # Other cases
    # Changing the signature
    # Changing the algorithm -> will pass at the moment as algorithm hardcoded
  end
end
