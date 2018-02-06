defmodule SignexTest do
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
    {:error, _reason} = SignEx.sign("hi", %{"signature" => "my-signature"}, %{public_key: "public", private_key: "private"})
  end

  describe "digest_valid?" do
    test "is valid hashing function is used and hashed content matches given digest" do
      content = "{\"this\": \"is content\"}"
      digest = SignEx.generate_digest(content, :sha256)
      assert SignEx.digest_valid?(content, digest)
    end

    test "is not valid when invalid digest string is passed in" do
      content = "{\"this\": \"is content\"}"
      refute SignEx.digest_valid?(content, "blah")
    end
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
      content = "My exciting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      assert true == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "enforcing algorithm type works", %{keypair: keypair} do
      content = "My exciting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      assert signature.algorithm == "rsa-sha512"
      signature = %{signature | algorithm: "ec-sha512"}
      assert {:error, :invalid_algorithm} == SignEx.verify(content, metadata, signature, keypair.public_key)
    end

    test "verify message with empty body", %{keypair: keypair} do
      content = ""
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      assert true == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "tampering with the content compromises the message", %{keypair: keypair} do
      content = "My exciting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      content = content <> "nefarious"
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "tampering with any metadata compromises the message", %{keypair: keypair} do
      content = "My exciting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = %{metadata | "some-content" => "new-value"}
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "deleting any metadata compromises the message", %{keypair: keypair} do
      content = "My exciting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = Map.delete(metadata, "some-content")
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "tampering with the digest compromises the message", %{keypair: keypair} do
      content = "My exciting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = %{metadata | "digest" => "SHA-512=some other string"}
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "deleting the digest compromises the message", %{keypair: keypair} do
      content = "My exciting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = Map.delete(metadata, "digest")
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end


    test "modifiying the signature compromises the message", %{keypair: keypair} do
      content = "My exciting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      signature = %{signature | signature: signature.signature <> "extra"}
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "metadata must have a string representation", %{keypair: keypair} do
      content = "My exciting message!!!"
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
      content = "My exciting message!!!"
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
      content = "My exciting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = Map.delete(metadata, "digest")
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "tampering with the content compromises the message", %{keypair: keypair} do
      content = "My exciting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      content = content <> "nefarious"
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "tampering with any metadata compromises the message", %{keypair: keypair} do
      content = "My exciting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = %{metadata | "some-content" => "new-value"}
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

    test "deleting any metadata compromises the message", %{keypair: keypair} do
      content = "My exciting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      metadata = Map.delete(metadata, "some-content")
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end


    test "modifiying the signature compromises the message", %{keypair: keypair} do
      content = "My exciting message!!!"
      metadata = %{"some-content" => "with-value"}
      {:ok, {metadata, signature}} = SignEx.sign(content, metadata, keypair)
      signature = %{signature | signature: signature.signature <> "extra"}
      assert false == SignEx.verified?(content, metadata, signature, keypair.public_key)
    end

  end

  describe "message signing" do
    setup do
      private_key = File.read!(Path.expand("../keys/ec_private_key.pem", __ENV__.file))
      public_key = File.read!(Path.expand("../keys/ec_public_key.pem", __ENV__.file))
      ec_keypair = %{private_key: private_key, public_key: public_key}

      private_key = File.read!(Path.expand("../keys/private_key.pem", __ENV__.file))
      public_key = File.read!(Path.expand("../keys/public_key.pem", __ENV__.file))
      rsa_keypair = %{private_key: private_key, public_key: public_key}

      {:ok,
        ec_keypair: ec_keypair,
        rsa_keypair: rsa_keypair,
      }
    end

    test "signature can be verified", %{ec_keypair: ec_keypair} do
      original = "Trust is Key"
      digest = :sha256

      assert {:ok, signature} = SignEx.sign_message(original, digest, ec_keypair)

      assert {:ok, :ec} = SignEx.verify_message(original, digest, signature, ec_keypair.public_key)
    end

    test "changing the original breaks the signature", %{ec_keypair: ec_keypair} do
      original = "Trust is Key"
      assert {:ok, signature} = SignEx.sign_message(original, :sha256, ec_keypair)

      assert {:error, :invalid_signature} = SignEx.verify_message(original <> "X", :sha256, signature, ec_keypair.public_key)
    end

    test "changing the digest breaks the signature", %{ec_keypair: ec_keypair} do
      original = "Trust is Key"
      assert {:ok, signature} = SignEx.sign_message(original, :sha256, ec_keypair)

      assert {:error, :invalid_signature} = SignEx.verify_message(original, :sha512, signature, ec_keypair.public_key)
    end

    test "using a different key breaks the signature", %{ec_keypair: ec_keypair, rsa_keypair: rsa_keypair} do
      original = "Trust is Key"
      assert {:ok, signature} = SignEx.sign_message(original, :sha256, ec_keypair)

      assert {:error, :invalid_signature} = SignEx.verify_message(original, :sha256, signature, rsa_keypair.public_key)
    end

    test "breaking base64 encoding breaks the signature", %{ec_keypair: ec_keypair} do
      original = "Trust is Key"
      assert {:ok, signature} = SignEx.sign_message(original, :sha256, ec_keypair)

      broken_signature = "*()" <> signature

      assert {:error, :invalid_signature_encoding} = SignEx.verify_message(original, :sha256, broken_signature, ec_keypair.public_key)
    end

    test "specifying an invalid digest returns a neat error", %{ec_keypair: ec_keypair} do
      original = "Trust is Key"
      assert {:error, :invalid_digest} = SignEx.sign_message(original, :foo, ec_keypair)
      assert {:error, :invalid_digest} = SignEx.verify_message(original, :bar, "irrelevant", ec_keypair.public_key)
    end
  end
end
