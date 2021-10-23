# frozen_string_literal: true

require "spec_helper"
require "serverspec"

default_user    = "root"
default_group   = "root"
es_package_name = "opensearch"
es_service_name = "opensearch"
es_config_dir = "/usr/local/opensearch/config"
es_user_name = "opensearch"
es_user_group = "opensearch"
cluster_name = "testcluster"
java_home = case os[:family]
            when "freebsd"
              "/usr/local/openjdk11"
            else
              "/usr/local/opensearch/jdk"
            end

plugins = [
  # XXX depending on versions, some plugins have -, others `_`.
  "opensearch[-_]security",
  "opensearch[-_]alerting"
]
es_extra_packages = []
extra_files = %w[
  opensearch-security/securityconfig/roles.yml
  opensearch-security/securityconfig/roles_mapping.yml
  opensearch-security/securityconfig/internal_users.yml
  opensearch-security/securityconfig/config.yml
]

es_root_dir = case os[:family]
              when "freebsd"
                "/usr/local/lib/opensearch"
              else
                "/usr/local/opensearch"
              end
es_plugin_command = "#{es_root_dir}/bin/opensearch-plugin"
es_plugins_directory = "#{es_root_dir}/plugins"
es_data_directory = "/var/lib/opensearch"
es_log_directory  = "/var/log/opensearch"
es_log_file = "#{es_log_directory}/#{cluster_name}.log"
public_certs = [
  "admin.pem",
  "node.pem",
  "root-ca.pem"
]
private_certs = [
  "admin-key.pem",
  "node-key.pem",
  "root-ca-key.pem"
]
os_admin_user = "admin"
os_admin_password = "admin"

case os[:family]
when "freebsd"
  default_group = "wheel"
  es_package_name = "opensearch"
  es_config_dir = "/usr/local/etc/opensearch"
  es_data_directory = "/var/db/opensearch"
when "openbsd"
  default_group = "wheel"
  es_user_name = "_opensearch"
  es_user_group = "_opensearch"
  es_data_directory = "/var/opensearch"
when "ubuntu"
  es_extra_packages = ["unzip"]
end

security_config_dir = "#{es_plugins_directory}/opensearch-security/securityconfig"
security_config_files = %w[
  action_groups.yml
  audit.yml
  config.yml
  internal_users.yml
  nodes_dn.yml
  roles.yml
  roles_mapping.yml
  tenants.yml
  whitelist.yml
]
jvm_option = "#{es_config_dir}/jvm.options"
log4j2_properties = "#{es_config_dir}/log4j2.properties"

describe file es_config_dir do
  it { should exist }
  it { should be_directory }
  it { should be_mode 755 }
  it { should be_owned_by es_user_name }
  it { should be_grouped_into es_user_group }
end

describe file(es_data_directory) do
  it { should be_directory }
  it { should be_owned_by es_user_name }
  it { should be_grouped_into es_user_group }
  it { should be_mode 755 }
end

describe file(es_log_directory) do
  it { should be_directory }
  it { should be_owned_by es_user_name }
  it { should be_grouped_into es_user_group }
  it { should be_mode 755 }
end

describe service(es_service_name) do
  it { should be_running }
end

es_extra_packages.each do |p|
  describe package p do
    it { should be_installed }
  end
end

case os[:family]
when "freebsd"
  describe package(es_package_name) do
    it { should be_installed }
  end
end

describe file jvm_option do
  it { should be_file }
  it { should be_mode 644 }
  it { should be_owned_by es_user_name }
  it { should be_grouped_into es_user_group }
  its(:content) { should match(Regexp.escape("Managed by ansible")) }
end

describe file log4j2_properties do
  it { should be_file }
  it { should be_mode 644 }
  it { should be_owned_by es_user_name }
  it { should be_grouped_into es_user_group }
  its(:content) { should match(/Managed by ansible/) }
end

case os[:family]
when "freebsd"
  describe file("/etc/rc.conf.d") do
    it { should be_directory }
    it { should be_mode 755 }
    it { should be_owned_by default_user }
    it { should be_grouped_into default_group }
  end

  describe file("/etc/rc.conf.d/opensearch") do
    it { should be_file }
    it { should be_mode 644 }
    it { should be_owned_by default_user }
    it { should be_grouped_into default_group }
    its(:content) { should match(/Managed by ansible/) }
  end
when "ubuntu"
  describe file("/etc/default/opensearch") do
    it { should be_file }
    it { should be_mode 644 }
    it { should be_owned_by default_user }
    it { should be_grouped_into default_group }
    its(:content) { should match(/Managed by ansible/) }
    its(:content) { should match(/MAX_OPEN_FILES=65535/) }
  end
when "redhat"
  describe file("/etc/sysconfig/opensearch") do
    it { should be_file }
    it { should be_mode 644 }
    it { should be_owned_by default_user }
    it { should be_grouped_into default_group }
    its(:content) { should match(/Managed by ansible/) }
    its(:content) { should match(/MAX_OPEN_FILES=65535/) }
  end
when "openbsd"
  describe file("/etc/opensearch/jvm.in") do
    it { should be_file }
    it { should be_mode 644 }
    it { should be_owned_by default_user }
    it { should be_grouped_into default_group }
    its(:content) { should match(/JAVA_OPTS="#{Regexp.escape("-XX:+UseCompressedOops")}"$/) }
  end
end

[9200, 9300, 80, 5601].each do |p|
  describe port(p) do
    it { should be_listening }
  end
end

describe file("#{es_config_dir}/opensearch.yml") do
  it { should be_file }
  it { should be_owned_by es_user_name }
  it { should be_grouped_into es_user_group }
  it { should be_mode 440 }
  its(:content_as_yaml) { should include("cluster.name" => "testcluster") }
  its(:content_as_yaml) { should include("node.name" => "testnode") }
  its(:content_as_yaml) { should include("network.publish_host" => ["10.0.2.15"]) }
  its(:content_as_yaml) { should include("http.cors.enabled" => "true") }
  its(:content_as_yaml) { should include("http.cors.allow-origin" => "*") }
  its(:content_as_yaml) { should include("http.cors.max-age" => 86_400) }
  its(:content_as_yaml) { should include("http.cors.allow-methods" => "OPTIONS, HEAD, GET, POST, PUT, DELETE") }
  its(:content_as_yaml) { should include("http.cors.allow-headers" => "X-Requested-With, Content-Type, Content-Length") }
  its(:content_as_yaml) { should include("http.cors.allow-credentials" => "true") }
end

describe file(es_plugins_directory) do
  it { should be_directory }
  case os[:family]
  when "freebsd"
    it { should be_owned_by default_user }
    it { should be_grouped_into default_group }
  else
    it { should be_owned_by es_user_name }
    it { should be_grouped_into  es_user_group }
  end
  it { should be_mode 755 }
end

plugins.each do |p|
  describe command("env JAVA_HOME=#{java_home} #{es_plugin_command} list") do
    its(:stdout) { should match(/^#{p}$/) }
    its(:stderr) { should eq "" }
    its(:exit_status) { should eq 0 }
  end
end

case os[:family]
when "freebsd"
  describe command("env JAVA_HOME=#{java_home} #{es_plugin_command} list") do
    # XXX does not work with FreeBSD
    its(:stdout) { should_not match(/opensearch-performance-analyzer/) }
    its(:stderr) { should eq "" }
    its(:exit_status) { should eq 0 }
  end
end

extra_files.each do |f|
  describe file "#{es_plugins_directory}/#{f}" do
    it { should be_file }
    case os[:family]
    when "freebsd"
      it { should be_owned_by default_user }
    else
      it { should be_owned_by es_user_name }
    end
    it { should be_mode 640 }
    it { should be_grouped_into es_user_group }
    its(:content) { should match(/Managed by ansible/) }
  end
end

public_certs.each do |c|
  describe file "#{es_config_dir}/#{c}" do
    it { should be_file }
    it { should be_mode 444 }
    it { should be_owned_by default_user }
    it { should be_grouped_into default_group }
    its(:content) { should match(/-----BEGIN CERTIFICATE-----/) }
    its(:content) { should match(/-----END CERTIFICATE-----/) }
  end
end

private_certs.each do |c|
  describe file "#{es_config_dir}/#{c}" do
    it { should be_file }
    it { should be_owned_by es_user_name }
    it { should be_grouped_into es_user_group }
    it { should be_mode c == "node-key.pem" ? 600 : 400 }
    its(:content) { should match(/-----BEGIN (?:RSA )?PRIVATE KEY-----/) }
    its(:content) { should match(/-----END (?:RSA )?PRIVATE KEY-----/) }
  end
end

security_config_files.each do |f|
  describe file "#{security_config_dir}/#{f}" do
    it { should exist }
    it { should be_file }
    its(:content) { should match(/Managed by ansible/) }
  end
end

describe file es_log_file do
  it { should exist }
  it { should be_file }
  its(:content) { should match(/Auditing of internal configuration is enabled/) }
end

describe command "curl -vv --user #{os_admin_user}:#{os_admin_password} --insecure https://localhost:9200" do
  its(:exit_status) { should eq 0 }
  its(:stderr) { should match(Regexp.escape("HTTP/1.1 200 OK")) }
end
