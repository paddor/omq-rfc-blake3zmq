# frozen_string_literal: true

# Benchmark: CurveZMQ (RbNaCl) vs BLAKE3ZMQ throughput
#
# Usage:
#   OMQ_DEV=1 bundle exec ruby bench/throughput.rb

require "bundler/setup"
require "protocol/zmtp"
require "protocol/zmtp/mechanism/curve"
require "omq/rfc/blake3zmq"
require "rbnacl"
require "socket"
require "io/stream"
require "async"
require "benchmark"
require "console"
Console.logger = Console::Logger.new(Console::Output::Null.new)

# ---------------------------------------------------------------------------
# Crypto backends
# ---------------------------------------------------------------------------

Blake3Crypto = OMQ::Blake3ZMQ::Crypto

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CurveMech  = Protocol::ZMTP::Mechanism::Curve
Blake3Mech = Protocol::ZMTP::Mechanism::Blake3

def generate_keypair(crypto)
  sk = crypto::PrivateKey.generate
  [sk.public_key.to_s, sk.to_s]
end

def run_handshake(mech_class, crypto)
  server_pub, server_sec = generate_keypair(crypto)
  client_pub, client_sec = generate_keypair(crypto)
  server_mech = mech_class.server(server_pub, server_sec, crypto: crypto)
  client_mech = mech_class.client(client_pub, client_sec, server_key: server_pub, crypto: crypto)

  s1, s2 = UNIXSocket.pair
  server_io = IO::Stream::Buffered.wrap(s1)
  client_io = IO::Stream::Buffered.wrap(s2)

  server = Protocol::ZMTP::Connection.new(
    server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
  )
  client = Protocol::ZMTP::Connection.new(
    client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
  )

  Sync do
    [Async { server.handshake! }, Async { client.handshake! }].each(&:wait)
  end
ensure
  s1&.close
  s2&.close
end

def make_connected_mechs(mech_class, crypto)
  server_pub, server_sec = generate_keypair(crypto)
  client_pub, client_sec = generate_keypair(crypto)

  s1, s2 = UNIXSocket.pair
  server_io = IO::Stream::Buffered.wrap(s1)
  client_io = IO::Stream::Buffered.wrap(s2)

  server_mech = mech_class.server(server_pub, server_sec, crypto: crypto)
  client_mech = mech_class.client(client_pub, client_sec, server_key: server_pub, crypto: crypto)

  server = Protocol::ZMTP::Connection.new(
    server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
  )
  client = Protocol::ZMTP::Connection.new(
    client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
  )

  Sync do
    [Async { server.handshake! }, Async { client.handshake! }].each(&:wait)
  end

  s1.close
  s2.close

  # client sends, server receives
  [client_mech, server_mech]
end

def wire_to_frame(wire)
  flags = wire.getbyte(0)
  if (flags & 0x02) != 0
    body_size = wire.byteslice(1, 8).unpack1("Q>")
    body = wire.byteslice(9, body_size)
  else
    body_size = wire.getbyte(1)
    body = wire.byteslice(2, body_size)
  end
  Protocol::ZMTP::Codec::Frame.new(body, more: (flags & 0x01) != 0, command: (flags & 0x04) != 0)
end

def full_roundtrip(mech_class, crypto, payload, msg_count)
  server_pub, server_sec = generate_keypair(crypto)
  client_pub, client_sec = generate_keypair(crypto)
  server_mech = mech_class.server(server_pub, server_sec, crypto: crypto)
  client_mech = mech_class.client(client_pub, client_sec, server_key: server_pub, crypto: crypto)

  s1, s2 = UNIXSocket.pair
  server_io = IO::Stream::Buffered.wrap(s1)
  client_io = IO::Stream::Buffered.wrap(s2)

  server = Protocol::ZMTP::Connection.new(
    server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
  )
  client = Protocol::ZMTP::Connection.new(
    client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
  )

  Sync do
    [Async { server.handshake! }, Async { client.handshake! }].each(&:wait)

    msg_count.times do
      Async { client.send_message([payload]) }
      Async { server.receive_message }.wait
    end
  end

  s1.close
  s2.close
end

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

MESSAGE_SIZES = [64, 256, 1024, 4096, 16_384, 65_536, 131_072, 262_144]
HANDSHAKE_ROUNDS = 100
MSG_ROUNDS = 20_000

puts "=" * 60
puts "CurveZMQ (RbNaCl) vs BLAKE3ZMQ Benchmark"
puts "=" * 60
puts
puts "Ruby #{RUBY_VERSION} (#{RUBY_PLATFORM})"
puts "RbNaCl #{RbNaCl::VERSION} (libsodium FFI)"
puts "x25519 #{X25519::VERSION} (native C X25519)"
puts "ChaCha20Blake3 #{ChaCha20Blake3::VERSION} (Rust native AEAD + BLAKE3)"
puts

# ---------------------------------------------------------------------------
# 1. Handshake latency
# ---------------------------------------------------------------------------

puts "-" * 60
puts "Handshake latency (#{HANDSHAKE_ROUNDS} rounds, lower is better)"
puts "-" * 60
puts

Benchmark.bm(22) do |x|
  x.report("CurveZMQ/RbNaCl") do
    HANDSHAKE_ROUNDS.times { run_handshake(CurveMech, RbNaCl) }
  end

  x.report("BLAKE3ZMQ") do
    HANDSHAKE_ROUNDS.times { run_handshake(Blake3Mech, Blake3Crypto) }
  end
end

puts

# ---------------------------------------------------------------------------
# 2. Message throughput (encrypt + decrypt, no IO)
# ---------------------------------------------------------------------------

puts "-" * 60
puts "Message encrypt + decrypt throughput (#{MSG_ROUNDS} msgs, higher MB/s is better)"
puts "-" * 60
puts

labels = ["CurveZMQ/RbNaCl", "BLAKE3ZMQ"]
header = "%-10s" % "Size"
labels.each { |l| header += "  %16s" % l }
puts header
puts "-" * (10 + labels.size * 18)

MESSAGE_SIZES.each do |size|
  payload = SecureRandom.random_bytes(size)
  rounds = size >= 16_384 ? MSG_ROUNDS / 10 : MSG_ROUNDS

  results = {}

  sender, receiver = make_connected_mechs(CurveMech, RbNaCl)
  5.times { receiver.decrypt(wire_to_frame(sender.encrypt(payload))) }

  t = Benchmark.realtime do
    rounds.times { receiver.decrypt(wire_to_frame(sender.encrypt(payload))) }
  end
  results["CurveZMQ/RbNaCl"] = (size * rounds) / t / 1_000_000.0

  sender, receiver = make_connected_mechs(Blake3Mech, Blake3Crypto)
  5.times { receiver.decrypt(wire_to_frame(sender.encrypt(payload))) }

  t = Benchmark.realtime do
    rounds.times { receiver.decrypt(wire_to_frame(sender.encrypt(payload))) }
  end
  results["BLAKE3ZMQ"] = (size * rounds) / t / 1_000_000.0

  line = "%-10s" % "#{size} B"
  labels.each { |l| line += "  %13.1f MB/s" % results[l] }
  puts line
end

puts

# ---------------------------------------------------------------------------
# 3. Full round-trip (handshake + N messages over UNIXSocket)
# ---------------------------------------------------------------------------

puts "-" * 60
puts "Full round-trip: handshake + 1000 messages over UNIXSocket"
puts "-" * 60
puts

all_configs = [
  ["CurveZMQ/RbNaCl", CurveMech, RbNaCl],
  ["BLAKE3ZMQ", Blake3Mech, Blake3Crypto],
]

[64, 1024, 65_536].each do |size|
  payload = SecureRandom.random_bytes(size)
  msg_count = 1000

  results = {}
  all_configs.each do |label, mech_class, crypto|
    t = Benchmark.realtime { full_roundtrip(mech_class, crypto, payload, msg_count) }
    mbps = (size * msg_count) / t / 1_000_000.0
    results[label] = { time: t, mbps: mbps }
  end

  slowest = results.values.max_by { |r| r[:time] }[:time]

  parts = results.map do |label, r|
    speedup = slowest / r[:time]
    "%s %7.1f ms (%5.1f MB/s) %5.1f\u00d7" % [label, r[:time] * 1000, r[:mbps], speedup]
  end

  printf "%6d B:  %s\n", size, parts.join("   ")
end

puts
puts "Done."
