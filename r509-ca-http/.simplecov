unless ENV["NO_COVERAGE"]
  SimpleCov.start do
    add_filter '/spec/'
  end
end
