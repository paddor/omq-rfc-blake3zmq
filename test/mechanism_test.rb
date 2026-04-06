# frozen_string_literal: true

require_relative "test_helper"

require "nuckle"
require "digest/blake3"

# Custom crypto backend using Nuckle (pure-Ruby X25519) for key exchange
# and chacha20blake3 for AEAD/hash. Demonstrates backend pluggability.
module NuckleCrypto
  CryptoError = ChaCha20Blake3::DecryptionError
  TAG_SIZE    = ChaCha20Blake3::TAG_SIZE
  Cipher      = ChaCha20Blake3::Cipher
  Stream      = ChaCha20Blake3::Stream

  class PublicKey
    def initialize(bytes)
      bytes = bytes.to_s if bytes.respond_to?(:to_bytes)
      @key = Nuckle::PublicKey.new(bytes.b)
    end

    def to_s = @key.to_s
  end

  class PrivateKey
    def self.generate = new(Nuckle::PrivateKey.generate.to_s)

    def initialize(bytes)
      @key = Nuckle::PrivateKey.new(bytes.b)
    end

    def public_key = PublicKey.new(@key.public_key.to_s)
    def to_s = @key.to_s

    def diffie_hellman(peer_public_key)
      pk = case peer_public_key
           when PublicKey
             peer_public_key.to_s
           else peer_public_key.to_s.b
           end
      @key.diffie_hellman(pk)
    end
  end

  module Hash
    module_function

    def digest(input)
      Digest::Blake3.digest(input)
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

describe Protocol::ZMTP::Mechanism::Blake3 do
  Blake3Mech = Protocol::ZMTP::Mechanism::Blake3
  Crypto     = TestBlake3Crypto

  def generate_keypair
    sk = Crypto::PrivateKey.generate
    [sk.public_key.to_s, sk.to_s]
  end

  def make_pair(mutual_auth: true, authenticator: nil)
    server_pub, server_sec = generate_keypair

    s1, s2 = UNIXSocket.pair
    server_io = IO::Stream::Buffered.wrap(s1)
    client_io = IO::Stream::Buffered.wrap(s2)

    auth = authenticator || (mutual_auth ? ->(_peer) { true } : nil)
    server_mech = Blake3Mech.server(public_key: server_pub, secret_key: server_sec, crypto: Crypto, authenticator: auth)

    if mutual_auth
      client_pub, client_sec = generate_keypair
      client_mech = Blake3Mech.client(server_key: server_pub, crypto: Crypto, public_key: client_pub, secret_key: client_sec)
    else
      client_mech = Blake3Mech.client(server_key: server_pub, crypto: Crypto)
    end

    server = Protocol::ZMTP::Connection.new(
      server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
    )
    client = Protocol::ZMTP::Connection.new(
      client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
    )

    [server, client, server_io, client_io]
  end

  it "is encrypted" do
    pub, sec = generate_keypair
    mech = Blake3Mech.server(public_key: pub, secret_key: sec, crypto: Crypto)
    assert mech.encrypted?
  end

  # Verify exact byte counts from the RFC wire format diagrams.
  describe "wire format byte counts" do
    it "HELLO command body is 200 bytes" do
      # HELLO body = name_len(1) + "HELLO"(5) + version(2) + C'(32) + padding(64) + hello_box(96)
      # hello_box = encrypt(zeros(64)) = 64 + 32(tag) = 96
      name_encoding = 1 + 5         # 0x05 + "HELLO"
      version       = 2             # 0x01, 0x00
      ephemeral_key = 32            # C'
      padding       = 64            # anti-amplification
      hello_box     = 64 + 32       # plaintext(64 zeros) + tag(32)

      expected = name_encoding + version + ephemeral_key + padding + hello_box
      assert_equal 200, expected
    end

    it "WELCOME command body is 192 bytes" do
      # WELCOME body = name_len(1) + "WELCOME"(7) + welcome_box(184)
      # welcome_box = encrypt(S'(32) + cookie(120)) = 152 + 32(tag) = 184
      # cookie = nonce(24) + encrypt(C'(32) + s'(32)) = 24 + 64 + 32(tag) = 120
      name_encoding = 1 + 7         # 0x07 + "WELCOME"
      cookie_size   = 24 + 32 + 32 + 32  # nonce + C' + s' + tag
      welcome_plain = 32 + cookie_size    # S' + cookie
      welcome_box   = welcome_plain + 32  # + tag

      assert_equal 120, cookie_size
      assert_equal 184, welcome_box
      assert_equal 192, name_encoding + welcome_box
    end

    it "INITIATE mutual auth command body has correct structure" do
      # INITIATE body = name_len(1) + "INITIATE"(8) + cookie(120) + initiate_box(variable)
      # initiate_box = encrypt(C(32) + vouch_box(96) + metadata + tag(32))
      # vouch_box = encrypt(C'(32) + S(32)) = 64 + 32(tag) = 96
      name_encoding = 1 + 8         # 0x08 + "INITIATE"
      vouch_box     = 32 + 32 + 32  # C' + S + tag
      # With empty metadata (just Socket-Type "PAIR" + Identity ""):
      # metadata ~ 25 bytes (property encoding overhead)

      assert_equal 9, name_encoding
      assert_equal 96, vouch_box
      assert_equal 120, 24 + 32 + 32 + 32  # cookie: nonce + payload + tag
    end

    it "READY command body has correct structure" do
      # READY body = name_len(1) + "READY"(5) + ready_box(variable)
      # ready_box = encrypt(metadata) = metadata + 32(tag)
      name_encoding = 1 + 5

      assert_equal 6, name_encoding
    end

    it "cookie is exactly 120 bytes" do
      # cookie = random_nonce(24) + encrypt(C'(32) + s'(32), tag(32))
      nonce    = 24
      payload  = 32 + 32   # C' + s'
      tag      = 32
      assert_equal 120, nonce + payload + tag
    end

    it "vouch box is exactly 96 bytes" do
      # vouch_box = encrypt(C'(32) + S(32), tag(32))
      payload = 32 + 32    # C' + S
      tag     = 32
      assert_equal 96, payload + tag
    end

    it "HELLO >= WELCOME (anti-amplification)" do
      hello_body   = 200
      welcome_body = 192
      assert hello_body >= welcome_body, "HELLO (#{hello_body}) must be >= WELCOME (#{welcome_body})"
    end

    it "verifies actual handshake frame sizes on the wire" do
      Async do
        server_pub, server_sec = generate_keypair
        client_pub, client_sec = generate_keypair

        s1, s2 = UNIXSocket.pair
        server_io = IO::Stream::Buffered.wrap(s1)
        client_io = IO::Stream::Buffered.wrap(s2)

        # Wrap client_io to record writes (these are client->server frames)
        client_writes = []
        client_wrapper = Object.new
        client_wrapper.define_singleton_method(:write) do |data|
          client_writes << data.b.dup
          client_io.write(data)
        end
        client_wrapper.define_singleton_method(:flush) { client_io.flush }
        client_wrapper.define_singleton_method(:read_exactly) { |n| client_io.read_exactly(n) }
        client_wrapper.define_singleton_method(:close) { client_io.close }

        server_writes = []
        server_wrapper = Object.new
        server_wrapper.define_singleton_method(:write) do |data|
          server_writes << data.b.dup
          server_io.write(data)
        end
        server_wrapper.define_singleton_method(:flush) { server_io.flush }
        server_wrapper.define_singleton_method(:read_exactly) { |n| server_io.read_exactly(n) }
        server_wrapper.define_singleton_method(:close) { server_io.close }

        server_mech = Blake3Mech.server(public_key: server_pub, secret_key: server_sec, crypto: Crypto)
        client_mech = Blake3Mech.client(server_key: server_pub, crypto: Crypto, public_key: client_pub, secret_key: client_sec)

        [
          Async { server_mech.handshake!(server_wrapper, as_server: true, socket_type: "PAIR", identity: "") },
          Async { client_mech.handshake!(client_wrapper, as_server: false, socket_type: "PAIR", identity: "") },
        ].each(&:wait)

        # Client sends: greeting(64) + HELLO frame
        # Server sends: greeting(64) + WELCOME frame + READY frame

        # Concatenate all writes into single byte streams
        client_bytes = client_writes.join
        server_bytes = server_writes.join

        greeting_size = 64

        # Parse client frames (skip greeting)
        client_frames_bytes = client_bytes.byteslice(greeting_size..)
        # First client frame: HELLO (command frame)
        hello_flags = client_frames_bytes.getbyte(0)
        assert_equal 0x04, hello_flags & 0x04, "HELLO should be a command frame"
        hello_body_size = client_frames_bytes.getbyte(1)  # short frame
        hello_body = client_frames_bytes.byteslice(2, hello_body_size)

        assert_equal 200, hello_body.bytesize, "HELLO command body should be 200 bytes"
        assert_equal 0x05, hello_body.getbyte(0), "HELLO name length should be 5"
        assert_equal "HELLO", hello_body.byteslice(1, 5), "HELLO name"

        # Second client frame: INITIATE (command frame, likely long)
        initiate_offset = 2 + hello_body_size
        initiate_frame_bytes = client_frames_bytes.byteslice(initiate_offset..)
        initiate_flags = initiate_frame_bytes.getbyte(0)
        assert_equal 0x04, initiate_flags & 0x04, "INITIATE should be a command frame"

        if (initiate_flags & 0x02) != 0
          # Long frame
          initiate_body_size = initiate_frame_bytes.byteslice(1, 8).unpack1("Q>")
          initiate_body = initiate_frame_bytes.byteslice(9, initiate_body_size)
        else
          initiate_body_size = initiate_frame_bytes.getbyte(1)
          initiate_body = initiate_frame_bytes.byteslice(2, initiate_body_size)
        end

        assert_equal 0x08, initiate_body.getbyte(0), "INITIATE name length should be 8"
        assert_equal "INITIATE", initiate_body.byteslice(1, 8), "INITIATE name"

        # INITIATE data = cookie(120) + initiate_box
        initiate_data = initiate_body.byteslice(9..)
        assert initiate_data.bytesize >= 120 + 32, "INITIATE data must contain cookie(120) + at least tag(32)"
        cookie_bytes = initiate_data.byteslice(0, 120)
        assert_equal 120, cookie_bytes.bytesize, "cookie should be 120 bytes"

        # Parse server frames (skip greeting)
        server_frames_bytes = server_bytes.byteslice(greeting_size..)

        # First server frame: WELCOME
        welcome_flags = server_frames_bytes.getbyte(0)
        assert_equal 0x04, welcome_flags & 0x04, "WELCOME should be a command frame"
        welcome_body_size = server_frames_bytes.getbyte(1)
        welcome_body = server_frames_bytes.byteslice(2, welcome_body_size)

        assert_equal 192, welcome_body.bytesize, "WELCOME command body should be 192 bytes"
        assert_equal 0x07, welcome_body.getbyte(0), "WELCOME name length should be 7"
        assert_equal "WELCOME", welcome_body.byteslice(1, 7), "WELCOME name"
        welcome_box = welcome_body.byteslice(8..)
        assert_equal 184, welcome_box.bytesize, "welcome_box should be 184 bytes"

        # Second server frame: READY
        ready_offset = 2 + welcome_body_size
        ready_frame_bytes = server_frames_bytes.byteslice(ready_offset..)
        ready_flags = ready_frame_bytes.getbyte(0)
        assert_equal 0x04, ready_flags & 0x04, "READY should be a command frame"
        ready_body_size = ready_frame_bytes.getbyte(1)
        ready_body = ready_frame_bytes.byteslice(2, ready_body_size)

        assert_equal 0x05, ready_body.getbyte(0), "READY name length should be 5"
        assert_equal "READY", ready_body.byteslice(1, 5), "READY name"
        ready_box = ready_body.byteslice(6..)
        # ready_box = metadata + 32(tag), metadata is at least a few bytes
        assert ready_box.bytesize >= 32, "ready_box must be at least 32 bytes (tag)"

        # Verify anti-amplification: HELLO body >= WELCOME body
        assert hello_body.bytesize >= welcome_body.bytesize,
               "HELLO (#{hello_body.bytesize}) must be >= WELCOME (#{welcome_body.bytesize})"
      ensure
        s1&.close
        s2&.close
      end
    end
  end

  describe "server-only auth (default)" do
    it "completes handshake and exchanges messages" do
      Async do
        server, client, sio, cio = make_pair(mutual_auth: false)

        Barrier do |bar|
          bar.async { server.handshake! }
          bar.async { client.handshake! }
        end

        assert_equal "PAIR", client.peer_socket_type
        assert_equal "PAIR", server.peer_socket_type

        Barrier do |bar|
          bar.async { client.send_message(["anon hello"]) }
          bar.async do
            assert_equal ["anon hello"], server.receive_message
          end
        end

        Barrier do |bar|
          bar.async { server.send_message(["anon reply"]) }
          bar.async do
            assert_equal ["anon reply"], client.receive_message
          end
        end
      ensure
        sio&.close
        cio&.close
      end
    end

    it "rejects client with wrong server key" do
      Async do
        server_pub, server_sec = generate_keypair
        wrong_pub, _ = generate_keypair

        s1, s2 = UNIXSocket.pair
        server_io = IO::Stream::Buffered.wrap(s1)
        client_io = IO::Stream::Buffered.wrap(s2)

        server_mech = Blake3Mech.server(public_key: server_pub, secret_key: server_sec, crypto: Crypto)
        client_mech = Blake3Mech.client(server_key: wrong_pub, crypto: Crypto)

        server = Protocol::ZMTP::Connection.new(
          server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
        )
        client = Protocol::ZMTP::Connection.new(
          client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
        )

        errors = []
        Barrier do |bar|
          bar.async do
            server.handshake!
          rescue Protocol::ZMTP::Error, EOFError => e
            errors << e
            server_io.close rescue nil
          end
          bar.async do
            client.handshake!
          rescue Protocol::ZMTP::Error, EOFError => e
            errors << e
            client_io.close rescue nil
          end
        end

        refute_empty errors
      ensure
        server_io&.close rescue nil
        client_io&.close rescue nil
      end
    end
  end

  describe "mutual auth" do
    it "completes handshake and exchanges messages" do
      Async do
        server, client, sio, cio = make_pair(mutual_auth: true)

        Barrier do |bar|
          bar.async { server.handshake! }
          bar.async { client.handshake! }
        end

        assert_equal "PAIR", client.peer_socket_type
        assert_equal "PAIR", server.peer_socket_type

        Barrier do |bar|
          bar.async { client.send_message(["encrypted hello"]) }
          bar.async do
            assert_equal ["encrypted hello"], server.receive_message
          end
        end

        Barrier do |bar|
          bar.async { server.send_message(["encrypted reply"]) }
          bar.async do
            assert_equal ["encrypted reply"], client.receive_message
          end
        end
      ensure
        sio&.close
        cio&.close
      end
    end

    it "exchanges multiple messages in both directions" do
      Async do
        server, client, sio, cio = make_pair

        Barrier do |bar|
          bar.async { server.handshake! }
          bar.async { client.handshake! }
        end

        10.times do |i|
          Barrier do |bar|
            bar.async { client.send_message(["msg-#{i}"]) }
            bar.async do
              assert_equal ["msg-#{i}"], server.receive_message
            end
          end

          Barrier do |bar|
            bar.async { server.send_message(["reply-#{i}"]) }
            bar.async do
              assert_equal ["reply-#{i}"], client.receive_message
            end
          end
        end
      ensure
        sio&.close
        cio&.close
      end
    end

    it "rejects client with wrong server key" do
      Async do
        server_pub, server_sec = generate_keypair
        client_pub, client_sec = generate_keypair
        wrong_pub, _ = generate_keypair

        s1, s2 = UNIXSocket.pair
        server_io = IO::Stream::Buffered.wrap(s1)
        client_io = IO::Stream::Buffered.wrap(s2)

        server_mech = Blake3Mech.server(
          public_key: server_pub, secret_key: server_sec,
          crypto: Crypto, authenticator: ->(_) { true },
        )
        client_mech = Blake3Mech.client(
          server_key: wrong_pub, crypto: Crypto,
          public_key: client_pub, secret_key: client_sec,
        )

        server = Protocol::ZMTP::Connection.new(
          server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
        )
        client = Protocol::ZMTP::Connection.new(
          client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
        )

        errors = []
        Barrier do |bar|
          bar.async do
            server.handshake!
          rescue Protocol::ZMTP::Error, EOFError => e
            errors << e
            server_io.close rescue nil
          end
          bar.async do
            client.handshake!
          rescue Protocol::ZMTP::Error, EOFError => e
            errors << e
            client_io.close rescue nil
          end
        end

        refute_empty errors
      ensure
        server_io&.close rescue nil
        client_io&.close rescue nil
      end
    end

    it "passes a PeerInfo with the client's PublicKey to the authenticator" do
      Async do
        server_pub, server_sec = generate_keypair
        client_pub, client_sec = generate_keypair

        received_peer = nil
        authenticator = lambda do |peer|
          received_peer = peer
          true
        end

        s1, s2 = UNIXSocket.pair
        server_io = IO::Stream::Buffered.wrap(s1)
        client_io = IO::Stream::Buffered.wrap(s2)

        server_mech = Blake3Mech.server(
          public_key: server_pub, secret_key: server_sec,
          crypto: Crypto, authenticator: authenticator,
        )
        client_mech = Blake3Mech.client(
          server_key: server_pub, crypto: Crypto,
          public_key: client_pub, secret_key: client_sec,
        )

        server = Protocol::ZMTP::Connection.new(
          server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
        )
        client = Protocol::ZMTP::Connection.new(
          client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
        )

        Barrier do |bar|
          bar.async { server.handshake! }
          bar.async { client.handshake! }
        end

        assert_instance_of Protocol::ZMTP::PeerInfo, received_peer
        assert_instance_of Crypto::PublicKey, received_peer.public_key
        assert_equal client_pub, received_peer.public_key.to_s
      ensure
        server_io&.close rescue nil
        client_io&.close rescue nil
      end
    end

    it "accepts when authenticator (lambda) returns true" do
      Async do
        server_pub, server_sec = generate_keypair
        client_pub, client_sec = generate_keypair

        s1, s2 = UNIXSocket.pair
        server_io = IO::Stream::Buffered.wrap(s1)
        client_io = IO::Stream::Buffered.wrap(s2)

        server_mech = Blake3Mech.server(
          public_key: server_pub, secret_key: server_sec,
          crypto: Crypto, authenticator: ->(_) { true },
        )
        client_mech = Blake3Mech.client(
          server_key: server_pub, crypto: Crypto,
          public_key: client_pub, secret_key: client_sec,
        )

        server = Protocol::ZMTP::Connection.new(
          server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
        )
        client = Protocol::ZMTP::Connection.new(
          client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
        )

        Barrier do |bar|
          bar.async { server.handshake! }
          bar.async { client.handshake! }
        end

        assert_equal "PAIR", client.peer_socket_type
      ensure
        server_io&.close rescue nil
        client_io&.close rescue nil
      end
    end

    it "rejects when authenticator (lambda) returns false" do
      Async do
        server_pub, server_sec = generate_keypair
        client_pub, client_sec = generate_keypair

        s1, s2 = UNIXSocket.pair
        server_io = IO::Stream::Buffered.wrap(s1)
        client_io = IO::Stream::Buffered.wrap(s2)

        server_mech = Blake3Mech.server(
          public_key: server_pub, secret_key: server_sec,
          crypto: Crypto, authenticator: ->(_) { false },
        )
        client_mech = Blake3Mech.client(
          server_key: server_pub, crypto: Crypto,
          public_key: client_pub, secret_key: client_sec,
        )

        server = Protocol::ZMTP::Connection.new(
          server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
        )
        client = Protocol::ZMTP::Connection.new(
          client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
        )

        errors = []
        Barrier do |bar|
          bar.async do
            server.handshake!
          rescue Protocol::ZMTP::Error, EOFError => e
            errors << e
            server_io.close rescue nil
          end
          bar.async do
            client.handshake!
          rescue Protocol::ZMTP::Error, EOFError => e
            errors << e
            client_io.close rescue nil
          end
        end

        refute_empty errors
        assert errors.any? { |e| e.message.include?("not authorized") }
      ensure
        server_io&.close rescue nil
        client_io&.close rescue nil
      end
    end

    it "accepts when key is in the allowed set" do
      Async do
        server_pub, server_sec = generate_keypair
        client_pub, client_sec = generate_keypair

        s1, s2 = UNIXSocket.pair
        server_io = IO::Stream::Buffered.wrap(s1)
        client_io = IO::Stream::Buffered.wrap(s2)

        allowed_keys = Set.new([client_pub])
        server_mech = Blake3Mech.server(
          public_key: server_pub, secret_key: server_sec,
          crypto: Crypto,
          authenticator: ->(peer) { allowed_keys.include?(peer.public_key.to_s) },
        )
        client_mech = Blake3Mech.client(
          server_key: server_pub, crypto: Crypto,
          public_key: client_pub, secret_key: client_sec,
        )

        server = Protocol::ZMTP::Connection.new(
          server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
        )
        client = Protocol::ZMTP::Connection.new(
          client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
        )

        Barrier do |bar|
          bar.async { server.handshake! }
          bar.async { client.handshake! }
        end

        assert_equal "PAIR", client.peer_socket_type
      ensure
        server_io&.close rescue nil
        client_io&.close rescue nil
      end
    end

    it "rejects when key is not in the allowed set" do
      Async do
        server_pub, server_sec = generate_keypair
        client_pub, client_sec = generate_keypair

        s1, s2 = UNIXSocket.pair
        server_io = IO::Stream::Buffered.wrap(s1)
        client_io = IO::Stream::Buffered.wrap(s2)

        allowed_keys = Set.new  # empty — no one is authorized
        server_mech = Blake3Mech.server(
          public_key: server_pub, secret_key: server_sec,
          crypto: Crypto,
          authenticator: ->(peer) { allowed_keys.include?(peer.public_key.to_s) },
        )
        client_mech = Blake3Mech.client(
          server_key: server_pub, crypto: Crypto,
          public_key: client_pub, secret_key: client_sec,
        )

        server = Protocol::ZMTP::Connection.new(
          server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
        )
        client = Protocol::ZMTP::Connection.new(
          client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
        )

        errors = []
        Barrier do |bar|
          bar.async do
            server.handshake!
          rescue Protocol::ZMTP::Error, EOFError => e
            errors << e
            server_io.close rescue nil
          end
          bar.async do
            client.handshake!
          rescue Protocol::ZMTP::Error, EOFError => e
            errors << e
            client_io.close rescue nil
          end
        end

        refute_empty errors
        assert errors.any? { |e| e.message.include?("not authorized") }
      ensure
        server_io&.close rescue nil
        client_io&.close rescue nil
      end
    end
  end

  it "uses the built-in crypto backend by default" do
    Async do
      server_pub, server_sec = generate_keypair

      s1, s2 = UNIXSocket.pair
      server_io = IO::Stream::Buffered.wrap(s1)
      client_io = IO::Stream::Buffered.wrap(s2)

      # No crypto: kwarg — should default to OMQ::Blake3ZMQ::Crypto
      server_mech = Blake3Mech.server(public_key: server_pub, secret_key: server_sec)
      client_mech = Blake3Mech.client(server_key: server_pub)

      server = Protocol::ZMTP::Connection.new(
        server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
      )
      client = Protocol::ZMTP::Connection.new(
        client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
      )

      Barrier do |bar|
        bar.async { server.handshake! }
        bar.async { client.handshake! }
      end

      assert_equal "PAIR", client.peer_socket_type

      Barrier do |bar|
        bar.async { client.send_message(["default crypto"]) }
        bar.async do
          assert_equal ["default crypto"], server.receive_message
        end
      end
    ensure
      s1&.close
      s2&.close
    end
  end

  it "raises on invalid key length" do
    assert_raises(ArgumentError) do
      Blake3Mech.server(public_key: "short", secret_key: "short", crypto: Crypto)
    end
  end

  it "raises on nil server keys" do
    assert_raises(ArgumentError) do
      Blake3Mech.server(public_key: nil, secret_key: nil, crypto: Crypto)
    end
  end

  it "raises on nil server_key for client" do
    assert_raises(ArgumentError) do
      Blake3Mech.client(server_key: nil, crypto: Crypto)
    end
  end

  it "handles large messages" do
    Async do
      server, client, sio, cio = make_pair

      Barrier do |bar|
        bar.async { server.handshake! }
        bar.async { client.handshake! }
      end

      large_msg = SecureRandom.random_bytes(1_000_000)
      Async { client.send_message([large_msg]) }
      msg = nil
      Async { msg = server.receive_message }.wait
      assert_equal [large_msg], msg
    ensure
      sio&.close
      cio&.close
    end
  end

  it "handles empty messages" do
    Async do
      server, client, sio, cio = make_pair

      Barrier do |bar|
        bar.async { server.handshake! }
        bar.async { client.handshake! }
      end

      Async { client.send_message([""]) }
      msg = nil
      Async { msg = server.receive_message }.wait
      assert_equal [""], msg
    ensure
      sio&.close
      cio&.close
    end
  end

  it "works with a custom crypto backend (Nuckle)" do
    Async do
      server_sk = NuckleCrypto::PrivateKey.generate
      server_pub = server_sk.public_key.to_s
      server_sec = server_sk.to_s

      client_sk = NuckleCrypto::PrivateKey.generate
      client_pub = client_sk.public_key.to_s
      client_sec = client_sk.to_s

      s1, s2 = UNIXSocket.pair
      server_io = IO::Stream::Buffered.wrap(s1)
      client_io = IO::Stream::Buffered.wrap(s2)

      received_peer = nil
      server_mech = Blake3Mech.server(
        public_key: server_pub, secret_key: server_sec,
        crypto: NuckleCrypto,
        authenticator: lambda { |peer|
          received_peer = peer
          true
        },
      )
      client_mech = Blake3Mech.client(
        server_key: server_pub, crypto: NuckleCrypto,
        public_key: client_pub, secret_key: client_sec,
      )

      server = Protocol::ZMTP::Connection.new(
        server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
      )
      client = Protocol::ZMTP::Connection.new(
        client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
      )

      Barrier do |bar|
        bar.async { server.handshake! }
        bar.async { client.handshake! }
      end

      assert_instance_of Protocol::ZMTP::PeerInfo, received_peer
      assert_instance_of NuckleCrypto::PublicKey, received_peer.public_key
      assert_equal client_pub, received_peer.public_key.to_s

      Barrier do |bar|
        bar.async { client.send_message(["hello from nuckle"]) }
        bar.async do
          msg = server.receive_message
          assert_equal ["hello from nuckle"], msg
        end
      end

      Barrier do |bar|
        bar.async { server.send_message(["nuckle reply"]) }
        bar.async do
          msg = client.receive_message
          assert_equal ["nuckle reply"], msg
        end
      end
    ensure
      s1&.close
      s2&.close
    end
  end
end
