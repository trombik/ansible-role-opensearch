# frozen_string_literal: true

require "spec_helper"

url = "https://localhost:9200"
curl_opts = "-v --user admin:admin --cacert /usr/local/etc/opensearch/root.pem"
describe command "curl #{curl_opts} #{url}/_cat/nodes" do
  its(:exit_status) { should eq 0 }
  its(:stderr) { should match(%r{HTTP/1.1 200 OK}) }
  its(:stdout) { should match(/^#{Regexp.escape("192.168.56.100")}/) }
  its(:stdout) { should match(/^#{Regexp.escape("192.168.56.101")}/) }
  its(:stdout) { should match(/^#{Regexp.escape("192.168.56.102")}/) }
  its(:stdout) { should match(/^#{Regexp.escape("192.168.56.200")}/) }
end

describe command "curl #{curl_opts} #{url}/_cluster/health" do
  its(:exit_status) { should eq 0 }
  its(:stderr) { should match(%r{HTTP/1.1 200 OK}) }
  its(:stdout_as_json) { should include("cluster_name" => "test-cluster") }
  its(:stdout_as_json) { should include("status" => "green") }
  its(:stdout_as_json) { should include("number_of_nodes" => 4) }
  its(:stdout_as_json) { should include("number_of_data_nodes" => 2) }
end
