require "rubygems"
require "bundler/setup"
require "ruby-saml"

request = Onelogin::Saml::Authrequest.new

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

created_request = request.create(saml_settings)

puts created_request.inspect