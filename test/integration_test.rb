# frozen_string_literal: true

require_relative "test_helper"
require "omq"

Blake3Mech = Protocol::ZMTP::Mechanism::Blake3
Crypto     = TestBlake3Crypto

describe "BLAKE3ZMQ integration (socket-level)" do
  def generate_keypair
    sk = Crypto::PrivateKey.generate
    [sk.public_key.to_s, sk.to_s]
  end


  def blake3_server(pub, sec, **opts)
    Blake3Mech.server(public_key: pub, secret_key: sec, **opts)
  end


  def blake3_client(server_key:, **opts)
    Blake3Mech.client(server_key: server_key, **opts)
  end


  def wait_connected(*sockets, timeout: 2)
    sockets.each do |s|
      Async::Task.current.with_timeout(timeout) { s.peer_connected.wait }
    end
  end


  describe "PUSH/PULL over TCP" do
    it "works end-to-end" do
      server_pub, server_sec = generate_keypair

      Sync do
        pull = OMQ::PULL.new
        pull.mechanism = blake3_server(server_pub, server_sec)
        pull.bind("tcp://127.0.0.1:0")
        port = pull.last_tcp_port

        push = OMQ::PUSH.new
        push.mechanism = blake3_client(server_key: server_pub)
        push.connect("tcp://127.0.0.1:#{port}")
        wait_connected(push)

        push << "encrypted hello"
        msg = pull.receive
        assert_equal ["encrypted hello"], msg
      ensure
        push&.close
        pull&.close
      end
    end
  end


  describe "REQ/REP over TCP" do
    it "works end-to-end" do
      server_pub, server_sec = generate_keypair

      Sync do |task|
        rep = OMQ::REP.new
        rep.mechanism = blake3_server(server_pub, server_sec)
        rep.bind("tcp://127.0.0.1:0")
        port = rep.last_tcp_port

        task.async do
          msg = rep.receive
          rep << msg.map(&:upcase)
        end

        req = OMQ::REQ.new
        req.mechanism = blake3_client(server_key: server_pub)
        req.connect("tcp://127.0.0.1:#{port}")

        req << "hello"
        reply = req.receive
        assert_equal ["HELLO"], reply
      ensure
        req&.close
        rep&.close
      end
    end
  end


  describe "PUB/SUB over IPC" do
    it "works end-to-end" do
      server_pub, server_sec = generate_keypair
      addr = "ipc://@omq-blake3-pubsub-#{$$}"

      Sync do |task|
        pub = OMQ::PUB.new
        pub.mechanism = blake3_server(server_pub, server_sec)
        pub.bind(addr)

        sub = OMQ::SUB.new
        sub.mechanism = blake3_client(server_key: server_pub)
        sub.connect(addr)
        sub.subscribe("")
        pub.subscriber_joined.wait

        task.async { pub << "encrypted news" }
        msg = sub.receive
        assert_equal ["encrypted news"], msg
      ensure
        pub&.close
        sub&.close
      end
    end


    it "prefix filtering works" do
      server_pub, server_sec = generate_keypair
      addr = "ipc://@omq-blake3-pubsub-prefix-#{$$}"

      Sync do |task|
        pub = OMQ::PUB.new
        pub.mechanism = blake3_server(server_pub, server_sec)
        pub.bind(addr)

        sub = OMQ::SUB.new
        sub.mechanism = blake3_client(server_key: server_pub)
        sub.connect(addr)
        sub.subscribe("topic.a")
        pub.subscriber_joined.wait

        task.async do
          pub << "topic.a first"
          pub << "topic.b filtered out"
          pub << "topic.a second"
        end

        msg1 = sub.receive
        msg2 = sub.receive
        assert_equal ["topic.a first"], msg1
        assert_equal ["topic.a second"], msg2
      ensure
        pub&.close
        sub&.close
      end
    end
  end


  describe "XPUB/XSUB over TCP" do
    it "works end-to-end" do
      server_pub, server_sec = generate_keypair

      Sync do |task|
        xpub = OMQ::XPUB.new
        xpub.mechanism = blake3_server(server_pub, server_sec)
        xpub.bind("tcp://127.0.0.1:0")
        port = xpub.last_tcp_port

        xsub = OMQ::XSUB.new
        xsub.mechanism = blake3_client(server_key: server_pub)
        xsub.connect("tcp://127.0.0.1:#{port}")
        wait_connected(xsub)
        xsub.send("\x01".b)
        xpub.subscriber_joined.wait

        task.async { xpub << "xpub news" }
        xsub.read_timeout = 2
        msg = xsub.receive
        assert_equal ["xpub news"], msg
      ensure
        xpub&.close
        xsub&.close
      end
    end
  end


  describe "Multiple clients" do
    it "supports multiple clients to one server" do
      server_pub, server_sec = generate_keypair

      Sync do |task|
        rep = OMQ::REP.new
        rep.mechanism = blake3_server(server_pub, server_sec)
        rep.bind("tcp://127.0.0.1:0")
        port = rep.last_tcp_port

        task.async do
          2.times do
            msg = rep.receive
            rep << msg.map(&:upcase)
          end
        end

        req1 = OMQ::REQ.new
        req1.mechanism = blake3_client(server_key: server_pub)
        req1.connect("tcp://127.0.0.1:#{port}")

        req2 = OMQ::REQ.new
        req2.mechanism = blake3_client(server_key: server_pub)
        req2.connect("tcp://127.0.0.1:#{port}")

        req1 << "from client 1"
        assert_equal ["FROM CLIENT 1"], req1.receive

        req2 << "from client 2"
        assert_equal ["FROM CLIENT 2"], req2.receive
      ensure
        req1&.close
        req2&.close
        rep&.close
      end
    end
  end


  describe "Multipart messages" do
    it "encrypts and decrypts multipart correctly" do
      server_pub, server_sec = generate_keypair

      Sync do
        pull = OMQ::PULL.new
        pull.mechanism = blake3_server(server_pub, server_sec)
        pull.bind("tcp://127.0.0.1:0")
        port = pull.last_tcp_port

        push = OMQ::PUSH.new
        push.mechanism = blake3_client(server_key: server_pub)
        push.connect("tcp://127.0.0.1:#{port}")
        wait_connected(push)

        push.send(["frame1", "frame2", "frame3"])
        msg = pull.receive
        assert_equal ["frame1", "frame2", "frame3"], msg
      ensure
        push&.close
        pull&.close
      end
    end
  end
end
