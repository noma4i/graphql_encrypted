class GraphqlEncrypted::Cable::Journal::Sink
  %i[debug info].each do |level|
    define_method(level) do |*|
      true
    end
  end

  %i[warn error fatal unknown].each do |level|
    define_method(level) do |*args, &block|
      GraphqlEncrypted.option(:logger).public_send(level, *args, &block)
    end
  end
end
