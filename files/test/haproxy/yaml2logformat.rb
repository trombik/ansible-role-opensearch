#!/usr/bin/env ruby

# converts yaml file to log-format configuration line for haproxy

require "json"
require "yaml"

def leaf?(value)
  value.key?("type")
end

def parse_leaf(_key, value)
  case value["type"].downcase
  when "ip", "string", "date"
    "'#{value['name']}'"
  when "numeric"
    value["name"]
  else
    raise format("unknown type: %s", value["type"])
  end
end

def parse(hash)
  result = {}
  hash.each_key do |key|
    result[key] = if leaf?(hash[key])
                    parse_leaf(key, hash[key])
                  else
                    parse(hash[key])
                  end
  end
  result
end

parsed = parse(YAML.load_file(ARGV[0]))

# "Everybody stay back. I know regular expresssions"
# https://xkcd.com/208/
#
# if a variable is quoted with double quotes, remove the double quotes.
# if a variable is quoted with single and double quotes, double quote it.
# and, a special case for captured variables.
format = parsed.to_json
               .gsub(/"(%[a-zA-Z]+)"/, "\\1")
               .gsub(/"'(%[a-zA-Z]+)'"/, "\"\\1\"")
               .gsub(/"'(%\[capture[^\]]+\])'"/, "\"\\1\"")
puts format("log-format '%s'", format)
