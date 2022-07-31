require 'uri'
require 'net/http'

loop do
  key = 'mysharedkey'
  data = Time.now.to_i.to_s
  data.slice!(-2,2)
  puts "message: #{data}"
  digest = OpenSSL::Digest.new('sha256')

  auth = OpenSSL::HMAC.hexdigest(digest, key, data)
  puts "digest: #{auth}"

  uri = URI("http://api.apivault.domain1.com/api/otp")
  req = Net::HTTP::Get.new(uri)
  req['X-Authenticity'] = auth
  req['Content-Type'] = 'application/json'

  res = Net::HTTP.start(uri.hostname, uri.port) { |http|
    http.request(req)
  }

  puts "Status code: #{res.code}"
  puts "Response body #{res.body}"
end
