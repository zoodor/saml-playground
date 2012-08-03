require "rubygems"
require "bundler/setup"
require "ruby-saml"
require "net/http"
require "base64"
require "htmlentities"

saml_authentication_request = Onelogin::Saml::Authrequest.new

def saml_settings
  settings = Onelogin::Saml::Settings.new

  #settings.assertion_consumer_service_index = 0
  #settings.attribute_consuming_service_index = 0
  #settings.assertion_consumer_service_url = "http://foo/saml/consume"
  settings.issuer                         = 'https://sp.example.com/SAML2'
  settings.idp_sso_target_url             = "https://idp.example.com/saml/signon/blah"
  #settings.idp_cert_fingerprint           = OneLoginAppCertFingerPrint
  settings.name_identifier_format         = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
  # Optional for most SAML IdPs
  #settings.authn_context = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

  settings
end

saml = saml_authentication_request.create_authentication_xml_doc(saml_settings)
saml_string = ""
saml.write(saml_string)

proxy_addr = 'localhost'
proxy_port = 8888

proxy_class = Net::HTTP::Proxy(proxy_addr, proxy_port)
proxy_class.start('localhost:8080') {|http|
  request = Net::HTTP::Post.new('/saml-receiver')
  puts "SAML to send: #{saml_string}"
  request.form_data =  {'SAMLRequest'=>Base64.encode64(HTMLEntities.new.encode(saml_string))}
  postData = http.request(request)
  puts postData.body
}