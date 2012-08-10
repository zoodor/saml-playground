/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.saml2.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.RandomAccessFile;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import uk.gov.gds.saml.DOMUtils;
import org.apache.xerces.dom.ElementNSImpl;
import org.joda.time.DateTime;
import org.opensaml.common.BaseTestCase;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.SecurityTestHelper;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.StaticCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import static uk.gov.gds.saml.SamlFacade.createFromXmlString;
import static uk.gov.gds.saml.SamlFacade.printDocument;

public class SignedAssertionTest extends BaseTestCase {

    /** Credential used for signing. */
    private Credential goodCredential;

    /** Verification credential that should fail to verify signature. */
    private BasicCredential badCredential;

    /** Builder of Assertions. */
    private AssertionBuilder assertionBuilder;

    /** Builder of Issuers. */
    private IssuerBuilder issuerBuilder;

    /** Builder of AuthnStatements. */
    private AuthnStatementBuilder authnStatementBuilder;

    /** Builder of AuthnStatements. */
    private SignatureBuilder signatureBuilder;

    /** Generator of element IDs. */
    private SecureRandomIdentifierGenerator idGenerator;

    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        super.setUp();

        KeyPair keyPair = SecurityTestHelper.generateKeyPair("RSA", 1024, null);
        goodCredential = SecurityHelper.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());

        keyPair = SecurityTestHelper.generateKeyPair("RSA", 1024, null);
        badCredential = SecurityHelper.getSimpleCredential(keyPair.getPublic(), null);

        assertionBuilder = (AssertionBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        issuerBuilder = (IssuerBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        authnStatementBuilder = (AuthnStatementBuilder) builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
        signatureBuilder = (SignatureBuilder) builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME);

        idGenerator = new SecureRandomIdentifierGenerator();
    }

    /**
     * Creates a simple Assertion, signs it and then verifies the signature.
     *
     * @throws MarshallingException thrown if the Assertion can not be marshalled into a DOM
     * @throws ValidationException thrown if the Signature does not validate
     * @throws SignatureException
     * @throws UnmarshallingException
     * @throws SecurityException
     */
    public void testAssertionSignature()
            throws Exception, ValidationException, SignatureException, UnmarshallingException, SecurityException, TransformerException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, XMLParserException {
        goodCredential = getSigningCredential("mykey");


        DateTime now = new DateTime();

        Assertion assertion = assertionBuilder.buildObject();
        assertion.setVersion(SAMLVersion.VERSION_20);
        String id = idGenerator.generateIdentifier();
        assertion.setID(id);
        assertion.setIssueInstant(now);

        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue("urn:example.org:issuer");
        assertion.setIssuer(issuer);

        AuthnStatement authnStmt = authnStatementBuilder.buildObject();
        authnStmt.setAuthnInstant(now);
        assertion.getAuthnStatements().add(authnStmt);

        Signature signature = signatureBuilder.buildObject();
        signature.setSigningCredential(goodCredential);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);
        assertion.setSignature(signature);

        Marshaller marshaller = marshallerFactory.getMarshaller(assertion);
        marshaller.marshall(assertion);
        Signer.signObject(signature);


        // Unmarshall new tree around DOM to avoid side effects and Apache xmlsec bug.
        Assertion signedAssertion =
                (Assertion) unmarshallerFactory.getUnmarshaller(assertion.getDOM()).unmarshall(assertion.getDOM());

        printDocument(signedAssertion.getDOM());

        StaticCredentialResolver credResolver = new StaticCredentialResolver(goodCredential);
        KeyInfoCredentialResolver kiResolver = SecurityTestHelper.buildBasicInlineKeyInfoResolver();
        ExplicitKeySignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(credResolver, kiResolver);

        CriteriaSet criteriaSet = new CriteriaSet( new EntityIDCriteria("urn:example.org:issuer") );
        assertTrue("Assertion signature was not valid",
                trustEngine.validate(signedAssertion.getSignature(), criteriaSet));


        String s = toString(signedAssertion);

        Assertion a = createFromXmlString(s);

        DOMUtils.compareNodes(signedAssertion.getDOM(), a.getDOM());
        assertEquals(toString(signedAssertion), toString(a));
        assertTrue("Assertion signature was not valid",
                trustEngine.validate(a.getSignature(), criteriaSet));

    }

    private String toString(Assertion signedAssertion) throws IOException, TransformerException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        printDocument(signedAssertion.getDOM(), out);
        return new String(out.toByteArray());
    }

    private Credential getSigningCredential(String keyName) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        BasicCredential credential = new BasicCredential();
        PublicKey publicKey = getPublicKey(keyName);
        credential.setPublicKey(publicKey);

        PrivateKey privateKey = getPrivateKey(keyName);

        credential.setPrivateKey(privateKey);
//        credential.setUsageType(UsageType.SIGNING);
        return credential;
    }

    private PublicKey getPublicKey(String keyName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        RandomAccessFile raf = new RandomAccessFile(keyName + ".pub", "r");
        byte[] buf = new byte[(int)raf.length()];
        raf.readFully(buf);
        raf.close();
        X509EncodedKeySpec kspec = new X509EncodedKeySpec(buf);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(kspec);
    }

    private PrivateKey getPrivateKey(String keyName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        RandomAccessFile raf = new RandomAccessFile(keyName + ".pk8", "r");
        byte[] buf = new byte[(int)raf.length()];
        raf.readFully(buf);
        raf.close();
        PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(kspec);
    }

    public static String aa = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_d29df547fe3b8272f8164448053210b8\" IssueInstant=\"2012-08-08T10:14:31.415Z\" Version=\"2.0\">\n" +
            "    <saml2:Issuer>urn:example.org:issuer</saml2:Issuer>\n" +
            "    <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "        <ds:SignedInfo>\n" +
            "            <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
            "            <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
            "            <ds:Reference URI=\"#_d29df547fe3b8272f8164448053210b8\">\n" +
            "                <ds:Transforms>\n" +
            "                    <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
            "                    <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
            "                </ds:Transforms>\n" +
            "                <ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n" +
            "                <ds:DigestValue>T6zpeqlJYdQuFMkJWkDDRY8IRCA=</ds:DigestValue>\n" +
            "            </ds:Reference>\n" +
            "        </ds:SignedInfo>\n" +
            "        <ds:SignatureValue>TftjbIB1oOUwOHdT7mJ2wJPiN3H1y0oMFqJjpYkxdNzzIdQUj04+B8duBn9nOAuo+D6VBLTaS3IA2mbLpDb12UXSkxU2S2fXgnTGIBDzv8NIpirmMT2D1i/MZEKsfN3T3oiHXgX/2XP75YrutPkpi9EOCVIGVyInYOsbq0bLERc=</ds:SignatureValue>\n" +
            "    </ds:Signature>\n" +
            "    <saml2:AuthnStatement AuthnInstant=\"2012-08-08T10:14:31.415Z\"/>\n" +
            "</saml2:Assertion>";

}