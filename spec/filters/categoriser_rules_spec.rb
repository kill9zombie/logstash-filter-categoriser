# encoding: utf-8
require "logger"
require "logstash/devutils/rspec/spec_helper"

require "logstash/filters/base"
require "logstash/namespace"

# Dummy filter just so that we can load LogStash::Filters::Categoriser::Rules
class LogStash::Filters::Categoriser < LogStash::Filters::Base
  def register
  end

  def filter(event)
    filter_matched(event)
  end
end

require "logstash/filters/categoriser/rules"



describe LogStash::Filters::Categoriser::Rules do

  before(:each) do
    @logger = Logger.new(STDOUT)
  end

  it "raises an error for a missing rules file" do
    missing_rules_file = File.expand_path("../../fixtures/missing.rules.json", __FILE__)

    filter_config = LogStash::Filters::Categoriser::Rules.new(@logger)
    expect{ filter_config.read_config(missing_rules_file) }.to raise_error(Errno::ENOENT)
  end

  it "won't load invalid JSON" do
    missing_rules_file = File.expand_path("../../fixtures/invalid_json.rules.json", __FILE__)

    filter_config = LogStash::Filters::Categoriser::Rules.new(@logger)
    expect{ filter_config.read_config(missing_rules_file) }.to raise_error(JSON::ParserError)
  end
end
