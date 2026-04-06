# frozen_string_literal: true

$VERBOSE = nil

require "minitest/autorun"
require "omq/rfc/blake3zmq"
require "socket"
require "io/stream"
require "async"

require "console"
Console.logger = Console::Logger.new(Console::Output::Null.new)

# Use the gem's built-in crypto backend for tests.
TestBlake3Crypto = OMQ::Blake3ZMQ::Crypto
