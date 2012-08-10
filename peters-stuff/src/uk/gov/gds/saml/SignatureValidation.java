package uk.gov.gds.saml;

import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static uk.gov.gds.saml.SamlFacade.KeySet.myKey;
import static uk.gov.gds.saml.SamlFacade.KeySet.myKey1;
import static uk.gov.gds.saml.SamlFacade.createCriteriaSet;
import static uk.gov.gds.saml.SamlFacade.createFromXmlString;
import static uk.gov.gds.saml.SamlFacade.createSignatureValidator;
import static uk.gov.gds.saml.SamlFacade.createTrustEngine;

public class SignatureValidation {

    @BeforeClass
    public static void init() throws ConfigurationException {
        DefaultBootstrap.bootstrap();
    }

    @Test
    public void shouldValidateAssertion() throws ValidationException, ConfigurationException, XMLParserException, UnmarshallingException, SecurityException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        SignatureValidator signatureValidator = createSignatureValidator(SamlFacade.KeySet.myKey);
        Assertion assertion = createFromXmlString(samlAssertion);

        signatureValidator.validate(assertion.getSignature());
    }

    @Test
    public void shouldValidateAssertionUsingEngine() throws ValidationException, ConfigurationException, XMLParserException, UnmarshallingException, SecurityException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        Assertion assertion = createFromXmlString(samlAssertion);

        assertTrue("Assertion signature was not valid", createTrustEngine(myKey).validate(assertion.getSignature(), createCriteriaSet()));
    }


    @Test(expected = ValidationException.class)
    public void shouldNotValidateWithWrongKey() throws ValidationException, ConfigurationException, XMLParserException, UnmarshallingException, SecurityException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        SignatureValidator sigValidator = createSignatureValidator(myKey1);
        Assertion assertion = createFromXmlString(samlAssertion);

        sigValidator.validate(assertion.getSignature());
    }

    @Test
    public void shouldNotValidateWithWrongKeyUsingEngine() throws ValidationException, ConfigurationException, XMLParserException, UnmarshallingException, SecurityException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        CriteriaSet criteriaSet = createCriteriaSet();
        Assertion assertion = createFromXmlString(samlAssertion);

        assertFalse("Assertion signature was valid", createTrustEngine(myKey1).validate(assertion.getSignature(), criteriaSet));
    }

    @Test
    public void shouldValidateResponse() throws ValidationException, ConfigurationException, XMLParserException, UnmarshallingException, SecurityException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        SignatureValidator signatureValidator = createSignatureValidator(myKey);
        Response response = createFromXmlString(samlResponse);

        signatureValidator.validate(response.getSignature());
        signatureValidator.validate(response.getAssertions().get(0).getSignature());
    }

    @Test(expected = ValidationException.class)
    public void shouldNotValidateResponseSignedInsideOut() throws ValidationException, ConfigurationException, XMLParserException, UnmarshallingException, SecurityException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        SignatureValidator signatureValidator = createSignatureValidator(myKey);
        Response response = createFromXmlString(samlResponseSignedInsideOut);

        signatureValidator.validate(response.getSignature());
    }

    @Test
    public void shouldValidateResponseSignedWithTwoDifferentKeys() throws ValidationException, ConfigurationException, XMLParserException, UnmarshallingException, SecurityException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        SignatureValidator assertionSignatureValidator = createSignatureValidator(myKey1);
        SignatureValidator responseSignatureValidator = createSignatureValidator(myKey);
        Response response = createFromXmlString(samlResponseSignedWithTwoDifferentKeys);

        responseSignatureValidator.validate(response.getSignature());
        assertionSignatureValidator.validate(response.getAssertions().get(0).getSignature());
    }

    private static String samlResponse = "<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"res\" Version=\"2.0\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#res\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>Tx46DYpjq87DOsO9lqxfY/YmAFQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>P10nf4+GQgUPZKBvNYBfRSmvYxoDT0AncpbcjLkHbDxCYtHJysrd80dLV7eQ/Xyw7hWJHORhrWTgvF5MeinYeqOx4DkqIrTORRPxuEL3k5Y1ANE1jPdDn7UQogIvUwmATlv+6FwLOB1/HaHx68v45fBTLQXnvIoX/8UrA4nevPg=</ds:SignatureValue></ds:Signature><saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"ass01\" IssueInstant=\"2012-08-08T14:47:57.233Z\" Version=\"2.0\"><saml2:Issuer>urn:example.org:issuer</saml2:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#ass01\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>4QT0UKA+ZUR3CZZcPa00+mgO7CE=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>XGyWAHUxO+OHx2PJPFdkTRCDMQCdKVJxplBt9QPyFqBsMb3A23v1TORyq/o+DQPvO0RYDq4lRNEQHUsKEuYovX4IxbzEAv9lY1kfEylGmyJVWxNPTJMZbbcOpo/lY5jdX9gItAJ7BLBTxyJZp7hERdP/QcGTpic/ZH1jxJ2pAko=</ds:SignatureValue></ds:Signature><saml2:AuthnStatement AuthnInstant=\"2012-08-08T14:47:57.312Z\"/></saml2:Assertion></saml2p:Response>";

    private static String samlResponseSignedInsideOut = "<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"res\" Version=\"2.0\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#res\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>cDPWykav8md9jf5Zo6P6g1e4BDs=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>sMan/OE7bsHtiTQk9iqfEu0WQKpQzzsRKqb2eePsoPMlNy/MDsq8SORQy0uFwnnX+KMoxoc9ivgOjyFua3HdrepPhacPqF0RJogZNbH8L3hw3AZVE3bPEOXFNErsyqLbr/qXnJ1kz55m0+AbQmzVzEF9qzExZrpqZ9e7Hpxb0y8=</ds:SignatureValue></ds:Signature><saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"ass01\" IssueInstant=\"2012-08-08T15:05:46.222Z\" Version=\"2.0\"><saml2:Issuer>urn:example.org:issuer</saml2:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#ass01\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>fQm0ywR9uP1z5DqCZSqllwVFdEk=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>uGHkfBeVa8HCS1muJ/6uush6iK1B9kheYa6IB8Nzwjcp625mkdUEuWAtVXPowVtivF4Xe0GyCsKmPJNZJwbuj5IeLKUJaHGrwj2aHVewnX1//ta4Z9ZbB3JpsoixTb41/lmfRT3Vhe1vpUnqVzhTQ8A9usBeMTpVnRZTiLm71j4=</ds:SignatureValue></ds:Signature><saml2:AuthnStatement AuthnInstant=\"2012-08-08T15:05:46.301Z\"/></saml2:Assertion></saml2p:Response>";

    private static String samlResponseSignedWithTwoDifferentKeys = "<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"res\" Version=\"2.0\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#res\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>lxpt13rVw4XqfsElDxV9vJYFd6s=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>enbB7qqdq75lJGHFm9PY3siYC7itnaoPqUSMMOLID1ELJjSn+lfFrZ9sbOSFDspOArzGB73pRPNHo/Y16e2C36dIo9ByxJQSDJu2DJqrM0RQKETNNbfFbJjzug+npF/cjmWbL2wZXjjQKZGlfh4AuiP7i6yVBiAPhvxATEWPEL0=</ds:SignatureValue></ds:Signature><saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"ass01\" IssueInstant=\"2012-08-08T15:12:34.541Z\" Version=\"2.0\"><saml2:Issuer>urn:example.org:issuer</saml2:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#ass01\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>U9M05YljU9DERxMhtBJrC+Ti9Lc=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>M6W5rAqzUh6NeFe2iptB0v2Z8qwGnOb8ec/1eJ+A7cPjhkJ09CO/z3htJ/MTcF1sNRK7aFh2WIMzejUbe/R0lQadfMWwUoY/D8eTuZssRmlGpM6E2QXVexutLFoL1UBmGpUBnNztZUAn7yUe+i5pZYbYD8wki8OO8eZyNC7yadM=</ds:SignatureValue></ds:Signature><saml2:AuthnStatement AuthnInstant=\"2012-08-08T15:12:34.620Z\"/></saml2:Assertion></saml2p:Response>\n";

    private static String samlAssertion = "<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"ass01\" IssueInstant=\"2012-08-08T13:43:40.908Z\" Version=\"2.0\"><saml2:Issuer>urn:example.org:issuer</saml2:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#ass01\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>/zpJs2OKrpQC+7cgVw7Vx8rWcbs=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>XzW5+y3TAwnyFqDvpRVnlpMvm4IdfMrIzk1IZLSu0B8IMxy6Hx1ubJuATQnBJHf/gm9UXcFdN+e3n7lfm/olyzXzB3mk25Yku7B1ojlxB/+R8yBODMWbOy1F9VLRRwg3489FvYuWjQYpsbHsReC5pbfJ2/lQMevDFsMqt5nqemk=</ds:SignatureValue></ds:Signature><saml2:AuthnStatement AuthnInstant=\"2012-08-08T13:43:40.908Z\"/></saml2:Assertion>";
}
