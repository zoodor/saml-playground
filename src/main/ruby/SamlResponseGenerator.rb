require "rubygems"
require "bundler/setup"
require "ruby-saml"
require "net/http"
require "base64"
require "htmlentities"
require "xmlsig"

require './Utilities'

def saml_settings
  settings = Onelogin::Saml::Settings.new

  settings.issuer                         = 'https://sp.example.com/SAML2'
  settings.idp_sso_target_url             = "https://idp.example.com/saml/signon/blah"
  #settings.idp_cert_fingerprint = "05:89:68:5A:C5:2B:FF:29:CD:37:17:CB:E5:20:14:BD:D1:33:EA:EF"
  settings.name_identifier_format         = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

  settings
end

doc = Xmlsig::XmlDoc.new()
doc.loadFromFile("../../../../saml-playground/sample-response-basic.xml")

#sign_response(doc)
sign_assertion(doc, Xmlsig::XPath.new('/samlp:Response/saml:Assertion')) #works, but fails to validate (because it's using xpointer?)
#sign_assertion(doc, Xmlsig::XPath.new('#xpointer(/foo)'))#fails to sign with XPathError
#sign_assertion(doc, Xmlsig::XPath.new("/[@id='identifier_3']"))#fails to sign with XPathError
#sign_assertion(doc, Xmlsig::XPath.new("id('identifier_3')"))#fails to sign with LibError
#sign_assertion(doc, Xmlsig::XPath.new("identifier_3"))#fails to sign with LibError

saml_string = doc.toString()

proxy_addr = 'localhost'
proxy_port = 8888
proxy_class = Net::HTTP::Proxy(proxy_addr, proxy_port)
proxy_class.start('localhost:8080') {|http|
  request = Net::HTTP::Post.new('/saml-response-receiver')

  puts "SAML to send:\n#{saml_string}"
  request.form_data =  {'SAMLRequest'=>Base64.encode64(HTMLEntities.new.encode(saml_string))}

  postData = http.request(request)
}