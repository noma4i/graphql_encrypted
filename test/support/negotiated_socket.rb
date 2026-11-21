require 'delegate'

class NegotiatedSocket < SimpleDelegator
  attr_accessor :hostname, :sync_close

  def initialize(io)
    super
    @steps = [:wait_writable, self]
  end

  def connect_nonblock(exception:)
    @steps.shift
  end

  def to_io
    __getobj__
  end
end
