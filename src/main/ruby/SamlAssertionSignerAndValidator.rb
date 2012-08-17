require 'ruby-saml'
require 'xmlsig'

require './Utilities'

def saml_settings
  settings = Onelogin::Saml::Settings.new

  settings.issuer                         = 'https://sp.example.com/SAML2'
  settings.idp_sso_target_url             = "https://idp.example.com/saml/signon/blah"
  #settings.idp_cert_fingerprint = "05:89:68:5A:C5:2B:FF:29:CD:37:17:CB:E5:20:14:BD:D1:33:EA:EF"
  settings.name_identifier_format         = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

  settings
end

saml_response_doc = Xmlsig::XmlDoc.new()
saml_response_doc.loadFromFile("../../../../saml-playground/sample-response-basic.xml")

puts "Response before signing:\n#{saml_response_doc.toString()}"

# NOTE: including namespaces causes signing to fail!?
#assertion_xpath.setXPath("id('identifier_3')")#doesn't work'
sign_assertion(saml_response_doc, Xmlsig::XPath.new("/samlp:Response/saml:Assertion"))

saml_response_to_send_string = saml_response_doc.toString()

puts "Response with signed assertion:\n#{saml_response_to_send_string}"

received_response_doc = Xmlsig::XmlDoc.new()
received_response_doc.loadFromString(saml_response_to_send_string)

#verifier = Xmlsig::Verifier.new(received_response_doc, Xmlsig::XPath.new('/samlp:Response/saml:Assertion/saml:Subject'))
verifier = Xmlsig::Verifier.new(received_response_doc)

response = Onelogin::Saml::Response.new(saml_response_to_send_string)
response.settings = saml_settings


verifying_cert = Xmlsig::X509Certificate.new()
verifying_cert.loadFromFile('/Users/mtaylor/Projects/IDA/cacert.pem', 'cert_pem')

puts "\n\nResponse is valid? #{verifier.verify()}"


