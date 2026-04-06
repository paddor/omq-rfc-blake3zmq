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

      # X25519 public key wrapper.
      class PublicKey
        # @param bytes [String] 32-byte public key
        def initialize(bytes)
          bytes = bytes.to_s if bytes.respond_to?(:to_bytes)
          @key = X25519::MontgomeryU.new(bytes.b)
        end


        # Returns the raw 32-byte public key.
        #
        # @return [String] 32-byte binary string
        def to_s = @key.to_bytes

        # @api private
        attr_reader :key
      end


      # X25519 private key wrapper with key generation and Diffie-Hellman.
      class PrivateKey
        # Generates a new random private key.
        #
        # @return [PrivateKey]
        def self.generate = new(X25519::Scalar.generate.to_bytes)

        # @param bytes [String] 32-byte secret key
        def initialize(bytes)
          @key = X25519::Scalar.new(bytes.b)
        end


        # Returns the corresponding public key.
        #
        # @return [PublicKey]
        def public_key = PublicKey.new(@key.public_key.to_bytes)

        # Returns the raw 32-byte secret key.
        #
        # @return [String] 32-byte binary string
        def to_s = @key.to_bytes

        # Performs X25519 Diffie-Hellman with a peer's public key.
        #
        # @param peer_public_key [PublicKey] peer's public key
        # @return [String] 32-byte shared secret
        def diffie_hellman(peer_public_key)
          pk = case peer_public_key
               when PublicKey
                 peer_public_key.key
               else
                 X25519::MontgomeryU.new(peer_public_key.to_s.b)
               end
          @key.diffie_hellman(pk).to_bytes
        end
      end


      # BLAKE3 hashing and key derivation functions.
      module Hash
        module_function

        # Computes a 32-byte BLAKE3 digest.
        #
        # @param input [String] data to hash
        # @return [String] 32-byte binary digest
        def digest(input)
          ChaCha20Blake3.digest(input)
        end


        # Derives a key using BLAKE3 key derivation.
        #
        # @param context [String] domain separation context string
        # @param material [String] input keying material
        # @param size [Integer] output length in bytes (default 32)
        # @return [String] derived key bytes
        def derive_key(context, material, size: 32)
          ChaCha20Blake3.derive_key(context, material, length: size)
        end
      end

      module_function

      # Generates cryptographically secure random bytes.
      #
      # @param n [Integer] number of bytes to generate
      # @return [String] random binary string
      def random_bytes(n)
        SecureRandom.random_bytes(n)
      end
    end
  end
end
