# encoding: utf-8
# frozen_string_literal: true
require "logstash/filters/base"
require "logstash/namespace"

#
# A way to categorise devices based on existing fields.
#
# In my scenario I have multiple types of devices all
# sending syslog logs.  I use this to quickly separate
# them in order to run a pipeline for each device type.
#
# Example config:
#
#   filter {
#     categoriser {
#       rules_file => "/etc/logstash/device_type.rules.json"
#       target => "device_type"
#       default_category => "unknown"
#     }
#   }
#
# .. with an example rules file:
#
# {
#   "cisco_asa_firewall": ["hostname", "contains", "-asa-"],
#   "cisco_pix_fwsm_firewall": [
#     "or", [
#       ["hostname", "contains", "-pix-"],
#       ["hostname", "contains", "-fwsm-"]]],
#   "web_servers": ["hostname", "starts_with", "web"]
# }
#
# This would replace the contents of the "device_type" field
# with the category in the rules file, ie "cisco_asa_firewall".
# If we don't match any rules then "device_type" will be set
# to "unknown".
#
class LogStash::Filters::Categoriser < LogStash::Filters::Base

  config_name "categoriser"

  require 'logstash/filters/categoriser/rules'

  # The rules filename, ie:
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

