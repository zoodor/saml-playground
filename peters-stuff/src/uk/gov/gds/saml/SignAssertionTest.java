package uk.gov.gds.saml;

import org.joda.time.DateTime;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.w3c.dom.Element;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;

import static uk.gov.gds.saml.SamlFacade.KeySet.myKey;
import static uk.gov.gds.saml.SamlFacade.KeySet.myKey1;
import static uk.gov.gds.saml.SamlFacade.createSignature;
import static uk.gov.gds.saml.SamlFacade.printDocument;

public class SignAssertionTest {


    /*
    to create a key set:
    openssl genrsa -out mykey.pem 1024
    openssl pkcs8 -topk8 -nocrypt -outform DER -in mykey.pem -out mykey.pk8
    openssl rsa -in mykey.pem -pubout -outform DER -out mykey.pub
     */
    @BeforeClass
    public static void init() throws ConfigurationException {
        DefaultBootstrap.bootstrap();
    }

    @Test
    public void shouldDoStuff() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, ConfigurationException, MarshallingException, TransformerException, SecurityException, SignatureException {

        Signature signature = createSignature(myKey);
        Signature signature1 = createSignature(myKey1);
        Signature signature2 = createSignature(myKey1);

        Response response = createResponse();
        Assertion assertion = createAssertion(null, "ass01");
        assertion.setSignature(signature);
//        response.getAssertions().get(0).setSignature(signature);
//        response.getAssertions().get(1).setSignature(signature1);
//        response.getAssertions().get(2).setSignature(signature2);

        Element marshall = Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
//        Signer.signObjects(Arrays.asList(signature, signature1, signature2));
        Signer.signObject(signature);
        printDocument(assertion.getDOM());
        printDocument(marshall);

    }

    @Test
    public void shouldCreateSignedResponse() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, ConfigurationException, MarshallingException, TransformerException, SecurityException, SignatureException {

        Signature responseSignature = createSignature(myKey);
        Signature assertSignature = createSignature(myKey);

        Response response = createResponse();
        response.setSignature(responseSignature);
        response.getAssertions().get(0).setSignature(assertSignature);

        Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);

        Signer.signObjects(Arrays.asList(assertSignature, responseSignature));
        printDocument(response.getDOM());
    }

    @Test
    public void shouldCreateSignedResponseUsingTwoDifferentKeys() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, ConfigurationException, MarshallingException, TransformerException, SecurityException, SignatureException {

        Signature responseSignature = createSignature(myKey);
        Signature assertSignature = createSignature(myKey1);

        Response response = createResponse();
        response.setSignature(responseSignature);
        response.getAssertions().get(0).setSignature(assertSignature);

        Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);

        Signer.signObjects(Arrays.asList(assertSignature, responseSignature));
        printDocument(response.getDOM());
    }

    private Assertion createAssertion(String issuerName, String id) throws ConfigurationException {
        // Get the builder factory
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

        // Get the assertion builder based on the assertion element name
        SAMLObjectBuilder<Assertion> builder = (SAMLObjectBuilder<Assertion>) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue("urn:example.org:issuer");

//        issuer.setValue(issuerName);

        // Create the assertion
        Assertion assertion = builder.buildObject();
        assertion.setIssueInstant(new DateTime());
        assertion.setID(id);
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(issuer);

        SAMLObjectBuilder<AuthnStatement> authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
        AuthnStatement authnStmt = authnStatementBuilder.buildObject();
        DateTime now = new DateTime();
        authnStmt.setAuthnInstant(now);
        assertion.getAuthnStatements().add(authnStmt);

        return assertion;
    }

    private Response createResponse () throws ConfigurationException {
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        SAMLObjectBuilder<Response> builder = (SAMLObjectBuilder<Response>) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);

        Response response = builder.buildObject();
        response.setID("res");
        response.getAssertions().add(createAssertion("sdfghjkl", "ass01"));
//        response.getAssertions().add(createAssertion("sdfghjkl", "ass02"));
//        response.getAssertions().add(createAssertion("sdfghjkl", "ass02"));
        return response;

    }
}
