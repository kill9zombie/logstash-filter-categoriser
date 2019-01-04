# encoding: utf-8
# frozen_string_literal: true
require "logstash/filters/base"
require "logstash/namespace"

# This example filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
#
# If we match more than one filter, print a warning and send
# to the unknown device type.
class LogStash::Filters::Categoriser < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   example {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "categoriser"

  require 'logstash/filters/categoriser/rules'

  # The config filename, ie:
  #   filter {
  #     categoriser {
  #       rules_file => "/etc/logstash/device_type.rules.json"
  #       target => "device_type"
  #     }
  #   }
  config :rules_file, :validate => :string
  config :target, :validate => :string, :default => "category"
  config :default_category, :validate => :string, :default => "unknown"

  public def register
    # Add instance variables
    filter_config = LogStash::Filters::Categoriser::Rules.new(@logger)
    @rules = filter_config.read_config(@rules_file)
  end

  public def filter(event)
    device_type = find_device_type(event)
    @logger.debug? && @logger.debug("Device type: #{device_type}")
    event.set(@target, device_type)

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end

  private def find_device_type(event)
    matched_type = @rules.find do |type, matcher|
      matcher.call(event)
    end || [@default_category, nil]

    matched_type.first
  end

end

