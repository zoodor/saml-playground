require "rubygems"
require "bundler/setup"
require "ruby-saml"
require "net/http"
require "base64"
require "htmlentities"
require "xmlsig"

saml_authentication_request = Onelogin::Saml::Authrequest.new

def saml_settings
  settings = Onelogin::Saml::Settings.new

  #settings.assertion_consumer_service_index = 0
  #settings.attribute_consuming_service_index = 0
  #settings.assertion_consumer_service_url = "http://foo/saml/consume"
  settings.issuer                         = 'https://sp.example.com/SAML2'
  settings.idp_sso_target_url             = "https://idp.example.com/saml/signon/blah"
  #settings.idp_cert_fingerprint           = OneLoginAppCertFingerPrint
  settings.idp_cert_fingerprint = "<signing-key-public-key>"
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

doc = Xmlsig::XmlDoc.new()
doc.loadFromString(saml_string)

key = Xmlsig::Key.new()
#key.loadFromFile('<path-on-your-machine>/my_saml_signing_key.txt.pub.cer', 'cert_pem', '')#doesn't work
key.loadFromFile('<path-on-your-machine>/private.pem', 'pem', '')#works
#key.loadFromFile('<path-on-your-machine>/trunk/ruby/t/res/tsik/keys/Alice.cer', 'cert_der', 'password')#doesn't work
#key.loadFromFile('<path-on-your-machine>/trunk/ruby/t/res/tsik/keys/alice.pfx', 'pkcs12', 'password')#works
signer = Xmlsig::Signer.new(doc, key)
#signer.addCertFromFile('<path-on-your-machine>/public.pem', 'pem')
#signer.attachPublicKey(1)
#x509key = Xmlsig::Key.new
#x509key.loadFromFile('<path-on-your-machine>/cacert.pem', 'cert_pem', '')
#x509cert = x509key.getCertificate()
x509cert = Xmlsig::X509Certificate.new()
certLoadResult = x509cert.loadFromFile('<path-on-your-machine>/cacert.pem', 'cert_pem')
#puts "X509 cert: #{x509cert.getVersion()}"
signer.addCert(x509cert)
signature_xpath = Xmlsig::XPath.new()
signature_xpath.addNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol')
signature_xpath.setXPath('/samlp:AuthnRequest/samlp:NameIDPolicy')

signer.useExclusiveCanonicalizer('')
signer.signInPlace(signature_xpath, true)
saml_string = doc.toString()

#NOTE: ruby-saml assumes that the signature element contains the signer's X509 certificate, but SAMLCore specifically states that this is optional (see 5.4.5 in SAMLCore)

proxy_class = Net::HTTP::Proxy(proxy_addr, proxy_port)
proxy_class.start('localhost:8080') {|http|
  request = Net::HTTP::Post.new('/saml-receiver')

  puts "SAML to send:\n#{saml_string}"
  request.form_data =  {'SAMLRequest'=>Base64.encode64(HTMLEntities.new.encode(saml_string))}

  postData = http.request(request)
  puts "\n\nSigned Response:\n#{postData.body}"

  response = Onelogin::Saml::Response.new(postData.body)
  response.settings = saml_settings
  puts "\n\nResponse is valid? #{response.validate!}"
}