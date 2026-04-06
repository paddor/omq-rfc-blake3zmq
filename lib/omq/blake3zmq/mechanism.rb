# frozen_string_literal: true

module Protocol
  module ZMTP
    module Mechanism
      # BLAKE3ZMQ security mechanism.
      #
      # Provides X25519 key exchange, ChaCha20-BLAKE3 AEAD encryption, and
      # BLAKE3 transcript hashing for ZMTP 3.1 connections.
      #
      # Crypto-backend-agnostic: pass any module that provides the required
      # interface via the +crypto:+ parameter.
      #
      # The crypto backend must provide:
      #   backend::PrivateKey.generate / .new(bytes)
      #     #public_key -> PublicKey, #to_s -> 32 bytes, #diffie_hellman(pub) -> 32 bytes
      #   backend::PublicKey.new(bytes)
      #     #to_s -> 32 bytes
      #   backend::Cipher.new(key)
      #     #encrypt(nonce, plaintext, aad:) -> ciphertext+tag
      #     #decrypt(nonce, ciphertext+tag, aad:) -> plaintext
      #   backend::Stream.new(key, nonce)
      #     #encrypt(plaintext, aad:) -> ciphertext+tag
      #     #decrypt(ciphertext+tag, aad:) -> plaintext
      #   backend::Hash.digest(input) -> 32 bytes
      #   backend::Hash.derive_key(context, material) -> 32 bytes
      #   backend::Hash.derive_key(context, material, size: n) -> n bytes
      #   backend.random_bytes(n) -> n bytes
      #   backend::CryptoError (exception class)
      #   backend::TAG_SIZE = 32
      #
      class Blake3
        MECHANISM_NAME = "BLAKE3"
        PROTOCOL_ID    = "BLAKE3ZMQ-1.0"
        TAG_SIZE       = 32
        KEY_SIZE       = 32
        NONCE_SIZE     = 24


        # Creates a BLAKE3 server mechanism.
        #
        # @param public_key [String] 32 bytes
        # @param secret_key [String] 32 bytes
        # @param crypto [Module] crypto backend
        # @param authenticator [#call, nil] called with a {PeerInfo} during
        #   authentication; must return truthy to allow the connection.
        #   When nil, any client with a valid vouch is accepted.
        # @return [Blake3]
        def self.server(public_key:, secret_key:, crypto: OMQ::Blake3ZMQ::Crypto, authenticator: nil)
          new(public_key:, secret_key:, crypto:, as_server: true, authenticator:)
        end


        # Creates a BLAKE3 client mechanism.
        #
        # @param server_key [String] 32 bytes (server permanent public key)
        # @param crypto [Module] crypto backend
        # @param public_key [String, nil] 32 bytes (or nil for auto-generated ephemeral identity)
        # @param secret_key [String, nil] 32 bytes (or nil for auto-generated ephemeral identity)
        # @return [Blake3]
        def self.client(server_key:, crypto: OMQ::Blake3ZMQ::Crypto, public_key: nil, secret_key: nil)
          new(public_key:, secret_key:, server_key:, crypto:, as_server: false)
        end


        # Initializes a new BLAKE3 mechanism instance.
        #
        # @param public_key [String, nil] 32-byte permanent public key
        # @param secret_key [String, nil] 32-byte permanent secret key
        # @param server_key [String, nil] 32-byte server permanent public key (client only)
        # @param crypto [Module] crypto backend module
        # @param as_server [Boolean] whether this instance acts as a server
        # @param authenticator [#call, nil] optional authenticator for server mode
        def initialize(public_key: nil, secret_key: nil, server_key: nil, crypto: OMQ::Blake3ZMQ::Crypto, as_server: false, authenticator: nil)
          @crypto        = crypto
          @as_server     = as_server
          @authenticator = authenticator

          if as_server
            validate_key!(public_key, "public_key")
            validate_key!(secret_key, "secret_key")
            @permanent_public = crypto::PublicKey.new(public_key.b)
            @permanent_secret = crypto::PrivateKey.new(secret_key.b)
            @cookie_key = crypto.random_bytes(KEY_SIZE)
          else
            validate_key!(server_key, "server_key")
            @server_public = crypto::PublicKey.new(server_key.b)
            if public_key && secret_key
              validate_key!(public_key, "public_key")
              validate_key!(secret_key, "secret_key")
              @permanent_public = crypto::PublicKey.new(public_key.b)
              @permanent_secret = crypto::PrivateKey.new(secret_key.b)
            else
              @permanent_secret = crypto::PrivateKey.generate
              @permanent_public = @permanent_secret.public_key
            end
          end

          @send_stream = nil
          @recv_stream = nil
        end


        # Resets stream state when duplicating the mechanism.
        #
        # @param source [Blake3] the original mechanism being duplicated
        def initialize_dup(source)
          super
          @send_stream = nil
          @recv_stream = nil
        end


        # Whether this mechanism encrypts traffic.
        #
        # @return [Boolean] always true
        def encrypted? = true

        # Returns a maintenance task that rotates the server cookie key.
        #
        # @return [Hash, nil] a hash with +:interval+ (seconds) and +:task+ (Proc), or nil for clients
        def maintenance
          return unless @as_server
          { interval: 60, task: -> { @cookie_key = @crypto.random_bytes(KEY_SIZE) } }.freeze
        end


        # Performs the BLAKE3ZMQ handshake over the given IO.
        #
        # Delegates to the client or server handshake depending on role.
        #
        # @param io [#write, #read_exactly] transport IO
        # @param as_server [Boolean] ignored (role is set at construction)
        # @param socket_type [String] ZMTP socket type name
        # @param identity [String] socket identity
        # @param qos [Integer] QoS level
        # @param qos_hash [String] QoS hash algorithm preference string
        # @return [Hash] peer metadata including +:peer_socket_type+, +:peer_identity+, +:peer_qos+, +:peer_qos_hash+
        def handshake!(io, as_server:, socket_type:, identity:, qos: 0, qos_hash: "")
          if @as_server
            server_handshake!(io, socket_type:, identity:, qos:, qos_hash:)
          else
            client_handshake!(io, socket_type:, identity:, qos:, qos_hash:)
          end
        end


        # Encrypts a ZMTP frame body for transmission.
        #
        # @param body [String] plaintext frame body
        # @param more [Boolean] whether the MORE flag is set
        # @param command [Boolean] whether this is a command frame
        # @return [String] wire-encoded encrypted frame (header + ciphertext)
        def encrypt(body, more: false, command: false)
          flags = 0
          flags |= 0x01 if more
          flags |= 0x04 if command

          ct = @send_stream.encrypt(body, aad: flags.chr)

          frame_size = ct.bytesize
          if frame_size > 255
            wire = String.new(encoding: Encoding::BINARY, capacity: 9 + frame_size)
            wire << (flags | 0x02).chr << [frame_size].pack("Q>")
          else
            wire = String.new(encoding: Encoding::BINARY, capacity: 2 + frame_size)
            wire << flags.chr << frame_size.chr
          end
          wire << ct
        end


        # Decrypts an encrypted ZMTP frame.
        #
        # @param frame [Codec::Frame] encrypted frame with body, more?, and command? attributes
        # @return [Codec::Frame] decrypted frame
        # @raise [Error] if decryption fails
        def decrypt(frame)
          flags = 0
          flags |= 0x01 if frame.more?
          flags |= 0x04 if frame.command?

          begin
            pt = @recv_stream.decrypt(frame.body, aad: flags.chr)
          rescue @crypto::CryptoError
            raise Error, "decryption failed"
          end
          Codec::Frame.new(pt, more: frame.more?, command: frame.command?)
        end

        private

        # ----------------------------------------------------------------
        # Client-side handshake
        # ----------------------------------------------------------------

        def client_handshake!(io, socket_type:, identity:, qos: 0, qos_hash: "")
          # Generate ephemeral keypair
          cn_secret = @crypto::PrivateKey.generate
          cn_public = cn_secret.public_key

          # Exchange greetings
          our_greeting = Codec::Greeting.encode(mechanism: MECHANISM_NAME, as_server: false)
          io.write(our_greeting)
          io.flush
          peer_greeting_bytes = io.read_exactly(Codec::Greeting::SIZE)
          peer_greeting = Codec::Greeting.decode(peer_greeting_bytes)
          unless peer_greeting[:mechanism] == MECHANISM_NAME
            raise Error, "expected #{MECHANISM_NAME} mechanism, got #{peer_greeting[:mechanism]}"
          end


          # h0 = H("BLAKE3ZMQ-1.0" || client_greeting || server_greeting)
          h = hash(PROTOCOL_ID + our_greeting + peer_greeting_bytes)

          # --- HELLO ---
          dh1         = cn_secret.diffie_hellman(@server_public)
          validate_dh!(dh1, "dh1")
          hello_key   = kdf("#{PROTOCOL_ID} HELLO key", dh1)
          hello_nonce = kdf24("#{PROTOCOL_ID} HELLO nonce", cn_public.to_s)
          hello_box   = @crypto::Cipher.new(hello_key).encrypt(hello_nonce, "\x00" * 64, aad: "HELLO")

          hello = "".b
          hello << "\x05HELLO"
          hello << "\x01\x00"           # version 1.0
          hello << cn_public.to_s       # 32 bytes
          hello << ("\x00" * 64)        # padding
          hello << hello_box            # 64 + 32(tag) = 96 bytes

          hello_wire = Codec::Frame.new(hello, command: true).to_wire
          io.write(hello_wire)
          io.flush

          # h1 = H(h0 || HELLO_wire_bytes)
          h = hash(h + hello_wire)

          # --- Read WELCOME ---
          welcome_frame = Codec::Frame.read_from(io)
          raise Error, "expected command frame" unless welcome_frame.command?
          welcome_cmd = Codec::Command.from_body(welcome_frame.body)
          raise Error, "expected WELCOME, got #{welcome_cmd.name}" unless welcome_cmd.name == "WELCOME"

          welcome_data = welcome_cmd.data
          welcome_box_size = KEY_SIZE + 120 + TAG_SIZE  # S'(32) + cookie(120) + tag(32) = 184
          raise Error, "WELCOME wrong size" unless welcome_data.bytesize == welcome_box_size

          welcome_key   = kdf("#{PROTOCOL_ID} WELCOME key", dh1)
          welcome_nonce = kdf24("#{PROTOCOL_ID} WELCOME nonce", h)
          begin
            welcome_plain = @crypto::Cipher.new(welcome_key).decrypt(welcome_nonce, welcome_data, aad: "WELCOME")
          rescue @crypto::CryptoError
            raise Error, "WELCOME decryption failed"
          end

          sn_public = @crypto::PublicKey.new(welcome_plain.byteslice(0, KEY_SIZE))
          cookie    = welcome_plain.byteslice(KEY_SIZE..)

          # h2 = H(h1 || WELCOME_wire_bytes)
          h = hash(h + welcome_frame.to_wire)

          # --- INITIATE ---
          dh2 = cn_secret.diffie_hellman(sn_public)
          validate_dh!(dh2, "dh2")

          initiate_key   = kdf("#{PROTOCOL_ID} INITIATE key", dh2 + h)
          initiate_nonce = kdf24("#{PROTOCOL_ID} INITIATE nonce", dh2 + h)

          props = { "Socket-Type" => socket_type, "Identity" => identity }
          if qos > 0
            props["X-QoS"]      = qos.to_s
            props["X-QoS-Hash"] = qos_hash unless qos_hash.empty?
          end
          metadata = Codec::Command.encode_properties(props)

          dh3 = @permanent_secret.diffie_hellman(sn_public)
          validate_dh!(dh3, "dh3")

          vouch_key   = kdf("#{PROTOCOL_ID} VOUCH key", dh3)
          vouch_nonce = kdf24("#{PROTOCOL_ID} VOUCH nonce", dh3)
          vouch_box   = @crypto::Cipher.new(vouch_key).encrypt(
            vouch_nonce, cn_public.to_s + @server_public.to_s, aad: "VOUCH"
          )

          initiate_plaintext = @permanent_public.to_s + vouch_box + metadata

          initiate_box = @crypto::Cipher.new(initiate_key).encrypt(
            initiate_nonce, initiate_plaintext, aad: "INITIATE"
          )

          initiate = "".b
          initiate << "\x08INITIATE"
          initiate << cookie
          initiate << initiate_box

          initiate_wire = Codec::Frame.new(initiate, command: true).to_wire
          io.write(initiate_wire)
          io.flush

          # h3 = H(h2 || INITIATE_wire_bytes)
          h = hash(h + initiate_wire)

          # --- Read READY ---
          ready_frame = Codec::Frame.read_from(io)
          raise Error, "expected command frame" unless ready_frame.command?
          ready_cmd = Codec::Command.from_body(ready_frame.body)

          if ready_cmd.name == "ERROR"
            reason = ready_cmd.data.bytesize > 0 ? ready_cmd.data.byteslice(1..) : ""
            raise Error, "server rejected: #{reason}"
          end
          raise Error, "expected READY, got #{ready_cmd.name}" unless ready_cmd.name == "READY"

          ready_key   = kdf("#{PROTOCOL_ID} READY key", dh2 + h)
          ready_nonce = kdf24("#{PROTOCOL_ID} READY nonce", dh2 + h)
          begin
            ready_plain = @crypto::Cipher.new(ready_key).decrypt(ready_nonce, ready_cmd.data, aad: "READY")
          rescue @crypto::CryptoError
            raise Error, "READY decryption failed"
          end

          peer_props       = Codec::Command.decode_properties(ready_plain)
          peer_socket_type = peer_props["Socket-Type"]
          peer_identity    = peer_props["Identity"] || ""
          peer_qos         = (peer_props["X-QoS"] || "0").to_i
          peer_qos_hash    = peer_props["X-QoS-Hash"] || ""

          # h4 = H(h3 || READY_wire_bytes)
          h = hash(h + ready_frame.to_wire)

          # Derive session keys
          derive_session_keys!(h, dh2, as_client: true)

          { peer_socket_type:, peer_identity:, peer_qos:, peer_qos_hash: }
        end


        # ----------------------------------------------------------------
        # Server-side handshake
        # ----------------------------------------------------------------

        def server_handshake!(io, socket_type:, identity:, qos: 0, qos_hash: "")
          # Exchange greetings
          our_greeting = Codec::Greeting.encode(mechanism: MECHANISM_NAME, as_server: true)
          io.write(our_greeting)
          io.flush
          peer_greeting_bytes = io.read_exactly(Codec::Greeting::SIZE)
          peer_greeting = Codec::Greeting.decode(peer_greeting_bytes)
          unless peer_greeting[:mechanism] == MECHANISM_NAME
            raise Error, "expected #{MECHANISM_NAME} mechanism, got #{peer_greeting[:mechanism]}"
          end


          # h0 = H("BLAKE3ZMQ-1.0" || client_greeting || server_greeting)
          # Note: peer is the client here
          h = hash(PROTOCOL_ID + peer_greeting_bytes + our_greeting)

          # --- Read HELLO ---
          hello_frame = Codec::Frame.read_from(io)
          raise Error, "expected command frame" unless hello_frame.command?
          hello_cmd = Codec::Command.from_body(hello_frame.body)
          raise Error, "expected HELLO, got #{hello_cmd.name}" unless hello_cmd.name == "HELLO"

          hdata = hello_cmd.data
          raise Error, "HELLO wrong size (#{hdata.bytesize})" unless hdata.bytesize == 194

          # version(2) + C'(32) + padding(64) + hello_box(96)
          cn_public_bytes = hdata.byteslice(2, KEY_SIZE)
          hello_box_data  = hdata.byteslice(98, 96)

          cn_public = @crypto::PublicKey.new(cn_public_bytes)
          dh1       = @permanent_secret.diffie_hellman(cn_public)
          validate_dh!(dh1, "dh1")

          hello_key   = kdf("#{PROTOCOL_ID} HELLO key", dh1)
          hello_nonce = kdf24("#{PROTOCOL_ID} HELLO nonce", cn_public_bytes)
          begin
            @crypto::Cipher.new(hello_key).decrypt(hello_nonce, hello_box_data, aad: "HELLO")
          rescue @crypto::CryptoError
            raise Error, "HELLO decryption failed"
          end


          # h1 = H(h0 || HELLO_wire_bytes)
          h = hash(h + hello_frame.to_wire)

          # --- WELCOME ---
          sn_secret = @crypto::PrivateKey.generate
          sn_public = sn_secret.public_key

          # Cookie: encrypt C' || s' under short-lived cookie key
          cookie_nonce = @crypto.random_bytes(NONCE_SIZE)
          cookie_key   = kdf("#{PROTOCOL_ID} cookie", @cookie_key)
          cookie_box   = @crypto::Cipher.new(cookie_key).encrypt(
            cookie_nonce, cn_public.to_s + sn_secret.to_s, aad: "COOKIE"
          )
          cookie = cookie_nonce + cookie_box  # 24 + 64 + 32(tag) = 120 bytes

          # Welcome box: encrypt S' || cookie
          welcome_key   = kdf("#{PROTOCOL_ID} WELCOME key", dh1)
          welcome_nonce = kdf24("#{PROTOCOL_ID} WELCOME nonce", h)
          welcome_box   = @crypto::Cipher.new(welcome_key).encrypt(
            welcome_nonce, sn_public.to_s + cookie, aad: "WELCOME"
          )

          welcome = "".b
          welcome << "\x07WELCOME"
          welcome << welcome_box

          welcome_wire = Codec::Frame.new(welcome, command: true).to_wire
          io.write(welcome_wire)
          io.flush

          # h2 = H(h1 || WELCOME_wire_bytes)
          h = hash(h + welcome_wire)

          # Server is stateless here — discard sn_secret.
          # In practice we keep it for the test/simple path;
          # a high-performance server would rely solely on the cookie.

          # --- Read INITIATE ---
          init_frame = Codec::Frame.read_from(io)
          raise Error, "expected command frame" unless init_frame.command?
          init_cmd = Codec::Command.from_body(init_frame.body)
          raise Error, "expected INITIATE, got #{init_cmd.name}" unless init_cmd.name == "INITIATE"

          idata = init_cmd.data
          raise Error, "INITIATE too short" if idata.bytesize < 120 + TAG_SIZE

          # Decrypt cookie to recover C' and s'
          recv_cookie       = idata.byteslice(0, 120)
          recv_cookie_nonce = recv_cookie.byteslice(0, NONCE_SIZE)
          recv_cookie_box   = recv_cookie.byteslice(NONCE_SIZE..)

          begin
            cookie_plain = @crypto::Cipher.new(cookie_key).decrypt(
              recv_cookie_nonce, recv_cookie_box, aad: "COOKIE"
            )
          rescue @crypto::CryptoError
            raise Error, "INITIATE cookie verification failed"
          end

          cn_public = @crypto::PublicKey.new(cookie_plain.byteslice(0, KEY_SIZE))
          sn_secret = @crypto::PrivateKey.new(cookie_plain.byteslice(KEY_SIZE, KEY_SIZE))

          dh2 = sn_secret.diffie_hellman(cn_public)
          validate_dh!(dh2, "dh2")

          initiate_key   = kdf("#{PROTOCOL_ID} INITIATE key", dh2 + h)
          initiate_nonce = kdf24("#{PROTOCOL_ID} INITIATE nonce", dh2 + h)

          initiate_ciphertext = idata.byteslice(120..)
          begin
            initiate_plain = @crypto::Cipher.new(initiate_key).decrypt(
              initiate_nonce, initiate_ciphertext, aad: "INITIATE"
            )
          rescue @crypto::CryptoError
            raise Error, "INITIATE decryption failed"
          end


          # Always parse C(32) + vouch_box(96) + metadata
          raise Error, "INITIATE plaintext too short" if initiate_plain.bytesize < KEY_SIZE + 96

          client_permanent = @crypto::PublicKey.new(initiate_plain.byteslice(0, KEY_SIZE))
          vouch_box        = initiate_plain.byteslice(KEY_SIZE, 96)
          metadata_bytes   = initiate_plain.byteslice(KEY_SIZE + 96..) || "".b

          # Verify vouch
          dh3 = sn_secret.diffie_hellman(client_permanent)
          validate_dh!(dh3, "dh3")
          vouch_key   = kdf("#{PROTOCOL_ID} VOUCH key", dh3)
          vouch_nonce = kdf24("#{PROTOCOL_ID} VOUCH nonce", dh3)
          begin
            vouch_plain = @crypto::Cipher.new(vouch_key).decrypt(vouch_nonce, vouch_box, aad: "VOUCH")
          rescue @crypto::CryptoError
            raise Error, "INITIATE vouch verification failed"
          end

          raise Error, "vouch wrong size" unless vouch_plain.bytesize == 64
          vouch_cn     = vouch_plain.byteslice(0, KEY_SIZE)
          vouch_server = vouch_plain.byteslice(KEY_SIZE, KEY_SIZE)

          unless vouch_cn == cn_public.to_s
            raise Error, "vouch client transient key mismatch"
          end
          unless vouch_server == @permanent_public.to_s
            raise Error, "vouch server key mismatch"
          end

          if @authenticator
            peer = PeerInfo.new(public_key: client_permanent)
            unless @authenticator.call(peer)
              send_error(io, "client key not authorized")
              raise Error, "client key not authorized"
            end
          end


          # h3 = H(h2 || INITIATE_wire_bytes)
          h = hash(h + init_frame.to_wire)

          # --- READY ---
          ready_props = { "Socket-Type" => socket_type, "Identity" => identity }
          if qos > 0
            ready_props["X-QoS"]      = qos.to_s
            ready_props["X-QoS-Hash"] = qos_hash unless qos_hash.empty?
          end
          ready_metadata = Codec::Command.encode_properties(ready_props)

          ready_key   = kdf("#{PROTOCOL_ID} READY key", dh2 + h)
          ready_nonce = kdf24("#{PROTOCOL_ID} READY nonce", dh2 + h)
          ready_box   = @crypto::Cipher.new(ready_key).encrypt(ready_nonce, ready_metadata, aad: "READY")

          ready = "".b
          ready << "\x05READY"
          ready << ready_box

          ready_wire = Codec::Frame.new(ready, command: true).to_wire
          io.write(ready_wire)
          io.flush

          # h4 = H(h3 || READY_wire_bytes)
          h = hash(h + ready_wire)

          props = Codec::Command.decode_properties(metadata_bytes)

          derive_session_keys!(h, dh2, as_client: false)

          {
            peer_socket_type: props["Socket-Type"],
            peer_identity:    props["Identity"] || "",
            peer_qos:         (props["X-QoS"] || "0").to_i,
            peer_qos_hash:    props["X-QoS-Hash"] || "",
          }
        end


        # ----------------------------------------------------------------
        # Session key derivation
        # ----------------------------------------------------------------

        def derive_session_keys!(h4, dh2, as_client:)
          ikm = h4 + dh2

          c2s_key   = kdf("#{PROTOCOL_ID} client->server key", ikm)
          c2s_nonce = kdf24("#{PROTOCOL_ID} client->server nonce", ikm)
          s2c_key   = kdf("#{PROTOCOL_ID} server->client key", ikm)
          s2c_nonce = kdf24("#{PROTOCOL_ID} server->client nonce", ikm)

          if as_client
            @send_stream = @crypto::Stream.new(c2s_key, c2s_nonce)
            @recv_stream = @crypto::Stream.new(s2c_key, s2c_nonce)
          else
            @send_stream = @crypto::Stream.new(s2c_key, s2c_nonce)
            @recv_stream = @crypto::Stream.new(c2s_key, c2s_nonce)
          end
        end


        # ----------------------------------------------------------------
        # Crypto helpers
        # ----------------------------------------------------------------

        def hash(input)
          @crypto::Hash.digest(input)
        end


        def kdf(context, material)
          @crypto::Hash.derive_key(context, material)
        end


        def kdf24(context, material)
          @crypto::Hash.derive_key(context, material, size: NONCE_SIZE)
        end


        def send_error(io, reason)
          error_body = "".b
          error_body << "\x05ERROR"
          error_body << reason.bytesize.chr << reason.b
          io.write(Codec::Frame.new(error_body, command: true).to_wire)
          io.flush
        rescue IOError
          # connection may already be broken
        end


        def validate_key!(key, name)
          raise ArgumentError, "#{name} is required" if key.nil?
          raise ArgumentError, "#{name} must be 32 bytes (got #{key.b.bytesize})" unless key.b.bytesize == KEY_SIZE
        end


        ZERO_DH = ("\x00" * KEY_SIZE).b.freeze


        def validate_dh!(shared_secret, label)
          raise Error, "#{label} produced all-zero output (low-order point)" if shared_secret == ZERO_DH
        end
      end
    end
  end
end
