# encoding: utf-8
# frozen_string_literal: true

require 'json'

class LogStash::Filters::Categoriser::RulesError < StandardError; end

class LogStash::Filters::Categoriser::Rules

  def initialize(logger)
    @logger = logger
  end

  def default_config
    default =<<-JSONCONFIG.gsub(/^ {6}/,'')
      {
        "cisco_asa_firewall": ["hostname", "contains", "-asa-"],
        "cisco_pix_firewall": [
          "or", [
            ["hostname", "contains", "-pix-"],
            ["hostname", "contains", "-fwsm-"]]],
        "f5_bigip": ["hostname", "contains", "-bigip-"],
        "checkpoint_ipso_firewall": ["hostname", "contains", "-nok-"],
        "checkpoint_gaia_firewall": ["hostname", "contains", "-cpg-"],
        "bluecoat_proxysg": ["hostname", "contains", "-bcsg-"],
        "bluecoat_proxyav": ["hostname", "contains", "-bcav-"]
      }
    JSONCONFIG
    JSON.load(default)
  end

  def read_config(filename)
    conf = JSON.load(File.read(filename))
    load_config(conf)
  end

  # Returns a hash:
  #   {"cisco_asa_firewall" => Proc}
  #
  # So
  def load_config(config)
    config.keys.reduce({}) do |acc, key|
      acc.merge({key => parse_checks(config[key])})
    end
  end

  # +checks+::
  #   ["and", [
  #     ["hostname", "contains", "-pix-"],
  #     ["hostname", "contains", "-fwsm-"]
  #   ]]
  # Returns a proc that you can pass 'event' into
  # The proc will return true or false.
  def parse_checks(checks)
    if !checks.is_a?(Array)
      raise ConfigError, "checks should be an array"
    end

    case checks.first
    when "and"
      if checks.last.is_a?(Array)
        Proc.new do |event|
          child_procs = checks.last.map {|check| parse_checks(check)}
          child_procs.all? {|child| child.call(event)}
        end
      else
        @logger.warn('Invalid config: "and" should be followed by an array, ie: ["and", [["hostname", "contains", "a"], ["hostname ", "contains", "b"]]]')
      end

    when "or"
      if checks.last.is_a?(Array)
        Proc.new do |event|
          child_procs = checks.last.map {|check| parse_checks(check)}
          child_procs.any? {|child| child.call(event)}
        end
      else
        @logger.warn('Invalid config: "or" should be followed by an array, ie: ["or", [["hostname", "contains", "a"], ["hostname", "contains", "b"]]]')
      end

    when "not"
      if checks.last.is_a?(Array)
        Proc.new do |event|
          not parse_checks(checks.last).call(event)
        end
      end
    else
      Proc.new { |event| load_check(checks).call(event) }
    end
  end


  # Loads a check, ie
  #   ["hostname", "contains", "-asa-"]
  #
  # .. where the format is:
  #
  #   [<field name>, <contains | regex>, <argument>]
  #
  # Returns a proc that can be used later to determine
  # if the check is true or false, ie:
  #
  # asa_check = load_check(["hostname", "contains", "-asa-"])
  # asa_check.(event)
  #
  def load_check(check)
    if check.length == 3
      if check.all? {|x| x.is_a?(String) }
        (check_field, check_command, check_argument) = check

        case check_command
        when "contains"
          Proc.new do |event|
            field_value = event.get(check_field)
            generic_check_ok?(check, check_field, field_value) && field_value.include?(check_argument)
          end
        when "regex"
          regex = Regexp.new(check_argument, Regexp::IGNORECASE)
          Proc.new do |event|
            field_value = event.get(check_field)
            generic_check_ok?(check, check_field, field_value) && regex.match?(field_value)
          end
        else
          @logger.warn("Invalid config: #{check}, the second argument must be one of: \"contains\", \"regex\"")
# TODO - see if it's ok to raise an error here?
          raise ConfigError, "Invalid config: #{check}, the second argument must be one of: \"contains\", \"regex\""
        end

      else
        @logger.warn("Invalid config: #{check}, all elements must be a string, ie: " + '["hostname", "contains", "-asa-"]')
        Proc.new{|event| false}
      end
    else
      @logger.warn("Invalid config: #{check}, expected three elements, ie: " + '["hostname", "contains", "-asa-"]')
      Proc.new{|event| false}
    end
  end

  private def generic_check_ok?(check, check_field, field_value)
    if field_value.nil?
      @logger.warn("vf_device_type - Could not read missing field, check #{check} returns false.", :field => check_field)
      false
    else
      if !field_value.is_a?(String)
        @logger.warn("vf_device_type - Field must be a string, check #{check} returns false (field was a(n) #{field_value.class}).", :field => check_field)
        false
      else
        true
      end
    end
  end

end

