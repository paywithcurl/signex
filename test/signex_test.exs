defmodule Mel.InvoiceApprovedConsumerTest do
  use ExUnit.Case, async: true

  @private_key File.read!(Path.expand("../keys/private_key.pem", __ENV__.file))
  @public_key  File.read!(Path.expand("../keys/public_key.pem", __ENV__.file))
  @message %{b: 2, a: 1, c: %{d: "fiz", e: nil}}
  @message_str Poison.encode!(@message)

  describe "#sign" do
    test "takes map as message and returns signatures and plaintext version of map" do
      {:ok, signature, plaintext} = SignEx.sign(@message, @private_key)
      assert String.match?(signature, ~r/^Signature algorithm=rsa-sha512,key_id=bc:d8:4c:0c:eb:dd:f2:61:4e:f6:da:08:f4:b3:e0:47,salt=[\w\/\+=]+,signature=[\w\/\+=]+$/)
      assert Poison.decode!(plaintext, keys: :atoms) == @message
    end

    test "takes string as message and returns signature and encoded plaintext" do
      {:ok, signature, plaintext} = SignEx.sign(@message_str, @private_key)
      assert String.match?(signature, ~r/^Signature algorithm=rsa-sha512,key_id=bc:d8:4c:0c:eb:dd:f2:61:4e:f6:da:08:f4:b3:e0:47,salt=[\w\/\+=]+,signature=[\w\/\+=]+$/)
      assert Poison.decode!(plaintext) == @message_str
    end

    test "takes nil as message and returns signature and encoded plaintext" do
      {:ok, signature, plaintext} = SignEx.sign(nil, @private_key)
      assert String.match?(signature, ~r/^Signature algorithm=rsa-sha512,key_id=bc:d8:4c:0c:eb:dd:f2:61:4e:f6:da:08:f4:b3:e0:47,salt=[\w\/\+=]+,signature=[\w\/\+=]+$/)
      assert Poison.decode!(plaintext) == nil
    end

    test "signatures are different every time for same message" do
      signatures = Enum.reduce([nil, nil, nil, nil], [], fn(msg, result) ->
        {:ok, signature, _} = SignEx.sign(msg, @private_key)
        result ++ [signature]
      end)
      assert Enum.count(Enum.uniq(signatures)) == 4
    end
  end

  describe "#verify" do
    @test_signature ~s(Signature algorithm=rsa-sha512,key_id=bc:d8:4c:0c:eb:dd:f2:61:4e:f6:da:08:f4:b3:e0:47,salt=vpThS1qOX09esU88NsFR2xFKdQ4PYDqynlSHCgYkW/m/3hFv+nXaKFeSbqo6IGwbONHPqr6lVFyyGsbcnrrN0g==,signature=aRgOTsqDDXtOZPIf3CaYnsZvr/R/RXpWK7OaS0caniz+CwOIrYu3lwXcstoMXJ3N4+QS/xqQnOroI0NT4C2GrHb+ro3JlHviirOtuFMJ8rxAnZ0ozXwzzqAj6FDhfpA1vNKB7yfxHykW7VJ1D871OlSb0RnLRr5TidJBxTBp5U7pVPArl+jou6XE5V7NnJ25dm2n/4LHlcGCTXMvzG424skmKylffW1NK9fbw0Q+x7jjlDvI+Y9hnVFDQBQIyOHin2465Lim39gebejX3dpVIasQPHp+/7m4A/kCSdQrdg2uz7QW/i74hHQ/FsWHkYbV71iiDHFM/4HZyyTgTDml6A==)

    test "takes signature and return :ok when it matches" do
      assert :ok = SignEx.verify(@message_str, @test_signature, @public_key)
    end

    test "takes signature and return error when signature doesn't match" do
      assert {:error, _} = SignEx.verify("blah", @test_signature, @public_key)
    end
  end
end
