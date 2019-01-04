# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/categoriser"

describe LogStash::Filters::Categoriser do
  describe "basic rules" do
    test_rules = File.expand_path("../../fixtures/test.rules.json", __FILE__)

    config <<-CONFIG
      filter {
        categoriser {
          rules_file => "#{test_rules}"
          target => "device_type"
        }
      }
    CONFIG

    # Simple match
    sample({"hostname" => "foo-asa-01"}) do
      expect(subject.get("device_type")).to eq('cisco_asa')
    end

    # "or"
    sample({"hostname" => "foo-dc-01"}) do
      expect(subject.get("device_type")).to eq('windows')
    end
    sample({"hostname" => "foo-sql-01"}) do
      expect(subject.get("device_type")).to eq('windows')
    end

    # "and"
    sample({"hostname" => "web01", "program" => "httpd"}) do
      expect(subject.get("device_type")).to eq('web_servers')
    end

    # "and" "not"
    sample({"hostname" => "foo-bigip-01", "message" => "test"}) do
      expect(subject.get("device_type")).to eq('bigip')
    end
    sample({"hostname" => "foo-bigip-01", "message" => "elephant test"}) do
      expect(subject.get("device_type")).to eq('unknown')
    end
  end

  describe "config defaults" do
    test_rules = File.expand_path("../../fixtures/test.rules.json", __FILE__)

    config <<-CONFIG
      filter {
        categoriser {
          rules_file => "#{test_rules}"
        }
      }
    CONFIG

    sample({"hostname" => "unmatched"}) do
      expect(subject.get("category")).to eq('unknown')
    end
  end

  describe "config" do
    test_rules = File.expand_path("../../fixtures/test.rules.json", __FILE__)

    # Once more with definition
    config <<-CONFIG
      filter {
        categoriser {
          rules_file => "#{test_rules}"
          target => "alice"
          default_category => "bob"
        }
      }
    CONFIG

    sample({"hostname" => "unmatched"}) do
      expect(subject.get("alice")).to eq('bob')
    end
  end

end
