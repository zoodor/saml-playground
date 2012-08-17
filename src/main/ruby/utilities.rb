

def sign_response(doc)
  key = Xmlsig::Key.new()
  key.loadFromFile('/Users/mtaylor/Projects/IDA/private.pem', 'pem', '')
  signer = Xmlsig::Signer.new(doc, key)

  x509cert = Xmlsig::X509Certificate.new()
  x509cert.loadFromFile('/Users/mtaylor/Projects/IDA/cacert.pem', 'cert_pem')
  signer.addCert(x509cert)

  signature_xpath = Xmlsig::XPath.new()
  signature_xpath.addNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol')
  signature_xpath.setXPath('/samlp:Response/samlp:Status')

  signer.useExclusiveCanonicalizer('')

  signer.signInPlace(signature_xpath, true)
end



def sign_assertion(doc, reference_xpath)
  key = Xmlsig::Key.new()
  key.loadFromFile('/Users/mtaylor/Projects/IDA/private.pem', 'pem', '')
  signer = Xmlsig::Signer.new(doc, key)
  x509cert = Xmlsig::X509Certificate.new()
  x509cert.loadFromFile('/Users/mtaylor/Projects/IDA/cacert.pem', 'cert_pem')
  signer.addCert(x509cert)

  signature_xpath = Xmlsig::XPath.new()
  signature_xpath.addNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol')
  signature_xpath.addNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion')
  signature_xpath.setXPath('/samlp:Response/saml:Assertion/saml:Subject')

  signer.useExclusiveCanonicalizer('')
  signer.addReference(reference_xpath) if reference_xpath

  signer.signInPlace(signature_xpath, true)
end