defmodule Mel.InvoiceApprovedConsumerTest do
  use ExUnit.Case, async: true

  @message %{b: 2, a: 1, c: %{d: "fiz", e: nil}}
  @message_str Poison.encode!(@message)

  describe "#sign with rsa keys" do
    setup do
      {:ok,
        private_key: File.read!(Path.expand("../keys/private_key.pem", __ENV__.file))
      }
    end

    test "takes map as message and returns signatures and plaintext version of map", %{private_key: private_key} do
      {:ok, signature, plaintext} = SignEx.sign(@message, private_key)
      assert String.match?(signature, ~r/^Signature algorithm=rsa-sha512,key_id=bc:d8:4c:0c:eb:dd:f2:61:4e:f6:da:08:f4:b3:e0:47,salt=[\w\/\+=]+,signature=[\w\/\+=]+$/)
      assert Poison.decode!(plaintext, keys: :atoms) == @message
    end

    test "takes string as message and returns signature and encoded plaintext", %{private_key: private_key} do
      {:ok, signature, plaintext} = SignEx.sign(@message_str, private_key)
      assert String.match?(signature, ~r/^Signature algorithm=rsa-sha512,key_id=bc:d8:4c:0c:eb:dd:f2:61:4e:f6:da:08:f4:b3:e0:47,salt=[\w\/\+=]+,signature=[\w\/\+=]+$/)
      assert Poison.decode!(plaintext) == @message_str
    end

    test "takes nil as message and returns signature and encoded plaintext", %{private_key: private_key} do
      {:ok, signature, plaintext} = SignEx.sign(nil, private_key)
      assert String.match?(signature, ~r/^Signature algorithm=rsa-sha512,key_id=bc:d8:4c:0c:eb:dd:f2:61:4e:f6:da:08:f4:b3:e0:47,salt=[\w\/\+=]+,signature=[\w\/\+=]+$/)
      assert Poison.decode!(plaintext) == nil
    end

    test "signatures are different every time for same message", %{private_key: private_key} do
      signatures = Enum.reduce([nil, nil, nil, nil], [], fn(msg, result) ->
        {:ok, signature, _} = SignEx.sign(msg, private_key)
        result ++ [signature]
      end)
      assert Enum.count(Enum.uniq(signatures)) == 4
    end
  end

  describe "#sign with ec keys" do
    setup do
      {:ok,
        private_key: File.read!(Path.expand("../keys/ec_private_key.pem", __ENV__.file))
      }
    end

    test "takes map as message and returns signatures and plaintext version of map", %{private_key: private_key} do
      {:ok, signature, plaintext} = SignEx.sign(@message, private_key)
      assert String.match?(signature, ~r/^Signature algorithm=ec-sha512,key_id=9d:94:44:7c:7d:fd:b3:3c:63:38:30:b8:fc:c8:de:b1,salt=[\w\/\+=]+,signature=[\w\/\+=]+$/)
      assert Poison.decode!(plaintext, keys: :atoms) == @message
    end

    test "takes string as message and returns signature and encoded plaintext", %{private_key: private_key} do
      {:ok, signature, plaintext} = SignEx.sign(@message_str, private_key)
      assert String.match?(signature, ~r/^Signature algorithm=ec-sha512,key_id=9d:94:44:7c:7d:fd:b3:3c:63:38:30:b8:fc:c8:de:b1,salt=[\w\/\+=]+,signature=[\w\/\+=]+$/)
      assert Poison.decode!(plaintext) == @message_str
    end

    test "takes nil as message and returns signature and encoded plaintext", %{private_key: private_key} do
      {:ok, signature, plaintext} = SignEx.sign(nil, private_key)
      assert String.match?(signature, ~r/^Signature algorithm=ec-sha512,key_id=9d:94:44:7c:7d:fd:b3:3c:63:38:30:b8:fc:c8:de:b1,salt=[\w\/\+=]+,signature=[\w\/\+=]+$/)
      assert Poison.decode!(plaintext) == nil
    end

    test "signatures are different every time for same message", %{private_key: private_key} do
      signatures = Enum.reduce([nil, nil, nil, nil], [], fn(msg, result) ->
        {:ok, signature, _} = SignEx.sign(msg, private_key)
        result ++ [signature]
      end)
      assert Enum.count(Enum.uniq(signatures)) == 4
    end
  end

  describe "#verify signed by rsa key" do
    setup do
      {:ok,
        public_key: File.read!(Path.expand("../keys/public_key.pem", __ENV__.file)),
        test_signature: ~s(Signature algorithm=rsa-sha512,key_id=bc:d8:4c:0c:eb:dd:f2:61:4e:f6:da:08:f4:b3:e0:47,salt=KpJtDhiH1gJo/hrdbKmTQC02Vz95RoKUT/JApLIiZm6ueygn6DgXIoE43agrjg2vLrph5ns5860GjymdbnF71w==,signature=en/VJ7zbmnjfQH7f8alFwtoaY9QD3QfmAPTBiK2lUXirA30OJy/nGeVLxgh78G/RATQbL/nQLH3WQP9fq/qe3e5zBtewmH2T0qKkn0qSey5XYe18PtVkd4oJdLzKQZEXnzb1N7BroNM52j/6oRo1NyX9fONC+adUb468IhZOKKoir5FA3wcY1tCZnfORDOWiq1A9yD3QHrr3h4HxthpWr3+WmyiCTYOdbmGRvHnGCdIZmVqQTS1gUhKiq8tg/Ad0G023DaOMmjvy+bD7426A5rvZZvpC2lkvjFYUNUg/KRFVpdLkhtDTxuv5yQDsblhjR2Sz6YuXso0OqK5FJFI7Wg==)
      }
    end

    test "takes signature and return :ok when it matches", %{test_signature: test_signature, public_key: public_key} do
      assert :ok = SignEx.verify(@message_str, test_signature, public_key)
    end

    test "takes signature and return error when signature doesn't match", %{test_signature: test_signature, public_key: public_key} do
      assert {:error, "Message doesn't match signature"} = SignEx.verify("blah", test_signature, public_key)
    end

    test "return error when invalid signature", %{public_key: public_key} do
      assert {:error, "invalid signature"} = SignEx.verify(@message_str, nil, public_key)
    end

    test "return error when invalid key", %{test_signature: test_signature} do
      assert {:error, "invalid public key"} = SignEx.verify(@message_str, test_signature, nil)
    end
  end

  describe "#verify signed by ec key" do
    setup do
      {:ok,
        public_key: File.read!(Path.expand("../keys/ec_public_key.pem", __ENV__.file)),
        test_signature: ~s(Signature algorithm=rsa-sha512,key_id=9d:94:44:7c:7d:fd:b3:3c:63:38:30:b8:fc:c8:de:b1,salt=mOUgYm31w5YdicKb1OiCuC3tCxwDhrzTJb18zGRTeXiN789zwC9Q2xbonSsc+ZWMDslsSlgtXieloLhC/UwEwQ==,signature=MIGIAkIBcDizu4+6Bu1cJ863f0KycdaJbwOUby6ynH64fxMhow1emv8ubzGca/sKgDTyN8ijd50FnrwQplWlnmsVjUVjlpoCQgF1OEq9EimaQjErYBKA0ETBKj1hfN5IxfvO8xtQMlUilFBAgjglmF6Yz51aeL+cHcp915p8ckQc0N562L0gehe3gw==)
      }
    end

    test "takes signature and return :ok when it matches", %{test_signature: test_signature, public_key: public_key} do
      assert :ok = SignEx.verify(@message_str, test_signature, public_key)
    end

    test "takes signature and return error when signature doesn't match", %{test_signature: test_signature, public_key: public_key} do
      assert {:error, "Message doesn't match signature"} = SignEx.verify("blah", test_signature, public_key)
    end

    test "return error when invalid signature", %{public_key: public_key} do
      assert {:error, "invalid signature"} = SignEx.verify(@message_str, nil, public_key)
    end

    test "return error when invalid key", %{test_signature: test_signature} do
      assert {:error, "invalid public key"} = SignEx.verify(@message_str, test_signature, nil)
    end
  end

  describe "#signature_params" do
    setup do
      {:ok,
        test_signature: ~s(Signature algorithm=rsa-sha512,key_id=bc:d8:4c:0c:eb:dd:f2:61:4e:f6:da:08:f4:b3:e0:47,salt=+gF1PZ9f0CkrhyC9dIGbryEMrEF7jlDyqk5Lua7ZAIygrMX9/DR65rdIEolUvZUueovNC4GQ2l+CrIW6dC80zw==,signature=JZKi0BhjBEjgBpU/oIYnowHTG4wym3FWTQXXCe8JWVI2Mw5GMb4tHQ4bI+eqbMRj8InHaYHqrlOtCy4PqtTC36vwrWeN9TjroLUc3Uusu7g8BVIrnR4lC2pXQQOfYPQ5VeQIXIsPI2T97pKtaOVDew2vlezbLn/kuNLI3ffHeTTb30XLpd7urqMI+pLXd1PFD8WGJ4YxG4oltmHWGuya85QXCbbEbJvrmllo3ShReB9flJfQluTXl7UHH3SHjFm5EIqyU4TVcG/phl87+IVYHpHOlLEmlgl0paiKtuWh0IQKknsq9rVVdQ5b9EPN//Az5N66+s7uY7BdaZQZMHBOKg==)
      }
    end

    test "splits signature in params and returns as map", %{test_signature: test_signature} do
      params = SignEx.signature_params(test_signature)
      assert params == %{
        "algorithm" => "rsa-sha512",
        "key_id" => "bc:d8:4c:0c:eb:dd:f2:61:4e:f6:da:08:f4:b3:e0:47",
        "salt" => "+gF1PZ9f0CkrhyC9dIGbryEMrEF7jlDyqk5Lua7ZAIygrMX9/DR65rdIEolUvZUueovNC4GQ2l+CrIW6dC80zw==",
        "signature" => "JZKi0BhjBEjgBpU/oIYnowHTG4wym3FWTQXXCe8JWVI2Mw5GMb4tHQ4bI+eqbMRj8InHaYHqrlOtCy4PqtTC36vwrWeN9TjroLUc3Uusu7g8BVIrnR4lC2pXQQOfYPQ5VeQIXIsPI2T97pKtaOVDew2vlezbLn/kuNLI3ffHeTTb30XLpd7urqMI+pLXd1PFD8WGJ4YxG4oltmHWGuya85QXCbbEbJvrmllo3ShReB9flJfQluTXl7UHH3SHjFm5EIqyU4TVcG/phl87+IVYHpHOlLEmlgl0paiKtuWh0IQKknsq9rVVdQ5b9EPN//Az5N66+s7uY7BdaZQZMHBOKg=="
      }
    end
  end
end
