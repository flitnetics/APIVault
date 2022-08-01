#!/usr/bin/env ruby
require 'uri'
require 'net/http'

# this is a CLI script to test the API protect feature
loop do
  key = 'mysharedkey'
  timestamp = Time.now.to_i.to_s
  puts "timestamp: #{timestamp}"
  digest = OpenSSL::Digest.new('sha256')

  auth = OpenSSL::HMAC.hexdigest(digest, key, timestamp)
  puts "digest: #{auth}"

  uri = URI("http://api.apivault.domain1.com/api/otp")
  req = Net::HTTP::Get.new(uri)
  req['X-Authenticity'] = auth
  req['Content-Type'] = 'application/json'
  req['X-Date'] = timestamp

  res = Net::HTTP.start(uri.hostname, uri.port) { |http|
    http.request(req)
  }

  puts "Status code: #{res.code}" 
  puts "Response body #{res.body}"
end
