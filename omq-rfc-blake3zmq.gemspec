# frozen_string_literal: true

require_relative "lib/omq/blake3zmq/version"

Gem::Specification.new do |s|
  s.name        = "omq-rfc-blake3zmq"
  s.version     = OMQ::Blake3ZMQ::VERSION
  s.authors     = ["Patrik Wenger"]
  s.email       = ["paddor@gmail.com"]
  s.summary     = "BLAKE3ZMQ security mechanism for OMQ"
  s.description = "BLAKE3ZMQ security mechanism (X25519 + ChaCha20-BLAKE3 AEAD) " \
                  "for the OMQ pure-Ruby ZeroMQ library."
  s.homepage    = "https://github.com/paddor/omq-rfc-blake3zmq"
  s.license     = "ISC"

  s.required_ruby_version = ">= 3.3"

  s.files = Dir["lib/**/*.rb", "README.md", "LICENSE"]

  s.add_dependency "protocol-zmtp", ">= 0.2"
  s.add_dependency "chacha20blake3", ">= 0.1"
  s.add_dependency "x25519", ">= 1.0"
end
