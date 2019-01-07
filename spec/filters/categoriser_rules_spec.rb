# encoding: utf-8
require "logger"
require "stringio"
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
    @logger.level = Logger::ERROR
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

  it "won't run invalid rules" do

    event = {"hostname" => "foo-asa-01"}
    def event.get(field)
      self[field]
    end

    filter_config = LogStash::Filters::Categoriser::Rules.new(@logger)

    invalid_rule = StringIO.new(%q({"cisco_asa": "invalid_rule"}))
    expect do
      rules = filter_config.read_config(invalid_rule)
      matched = rules.find {|type, matcher| matcher.call(event)}
    end.to raise_error(LogStash::Filters::Categoriser::RulesError)

    invalid_command = StringIO.new(%q({"cisco_asa": ["hostname", "invalid_command", "-asa-"]}))
    expect do
      rules = filter_config.read_config(invalid_command)
      matched = rules.find {|type, matcher| matcher.call(event)}
    end.to raise_error(LogStash::Filters::Categoriser::RulesError)

  end

  it "returns false for missing fields" do
    event = {"hostname" => "foo-asa-01"}
    def event.get(field)
      self[field]
    end

    filter_config = LogStash::Filters::Categoriser::Rules.new(@logger)

    missing_field_rule = StringIO.new(%q({"cisco_asa": ["alice", "contains", "-asa-"]}))
    expect(
      filter_config.read_config(missing_field_rule).any? {|type, matcher| matcher.call(event)}
    ).to be false
  end
end
