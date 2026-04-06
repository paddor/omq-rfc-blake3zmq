# frozen_string_literal: true

require "chacha20blake3"
require "x25519"
require "securerandom"

module OMQ
  module Blake3ZMQ
    # Default crypto backend: x25519 (native C) + chacha20blake3 (Rust native).
    module Crypto
      CryptoError = ChaCha20Blake3::DecryptionError
      TAG_SIZE    = ChaCha20Blake3::TAG_SIZE
      Cipher      = ChaCha20Blake3::Cipher
      Stream      = ChaCha20Blake3::Stream

      class PublicKey
        def initialize(bytes)
          bytes = bytes.to_s if bytes.respond_to?(:to_bytes)
          @key = X25519::MontgomeryU.new(bytes.b)
        end

        def to_s = @key.to_bytes

        # @api private
        attr_reader :key
      end

      class PrivateKey
        def self.generate = new(X25519::Scalar.generate.to_bytes)

        def initialize(bytes)
          @key = X25519::Scalar.new(bytes.b)
        end

        def public_key = PublicKey.new(@key.public_key.to_bytes)
        def to_s = @key.to_bytes

        def diffie_hellman(peer_public_key)
          pk = case peer_public_key
               when PublicKey then peer_public_key.key
               else X25519::MontgomeryU.new(peer_public_key.to_s.b)
               end
          @key.diffie_hellman(pk).to_bytes
        end
      end

      module Hash
        module_function

        def digest(input)
          ChaCha20Blake3.digest(input)
        end

        def derive_key(context, material, size: 32)
          ChaCha20Blake3.derive_key(context, material, length: size)
        end
      end

      module_function

      def random_bytes(n)
        SecureRandom.random_bytes(n)
      end
    end
  end
end
