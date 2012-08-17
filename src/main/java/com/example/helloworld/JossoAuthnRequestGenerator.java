package com.example.helloworld;

import com.example.helloworld.resources.SamlReceiver;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.bouncycastle.util.encoders.Base64;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class JossoAuthnRequestGenerator {

    public static void main(String[] args) throws org.opensaml.xml.signature.SignatureException, MarshallingException, CertificateEncodingException, KeyStoreException, ParserConfigurationException, ConfigurationException, IOException, TransformerException {
        DefaultBootstrap.bootstrap();

        Credential credential = SamlReceiver.getCredential();
        Document signedRequest = createSignedRequest(credential);

        System.out.println("Signed request:");
        Source source = new DOMSource(signedRequest);

        // Prepare the output file
        StringWriter docWriter = new StringWriter();
        Result result = new StreamResult(docWriter);

        // Write the DOM document to the file
        Transformer xformer = TransformerFactory.newInstance().newTransformer();
        xformer.transform(source, result);
        System.out.println(docWriter.toString());

        HttpClient client = new HttpClient();
        client.getHostConfiguration().setProxy("localhost", 8888);
        PostMethod method = new PostMethod("http://idp.example.org:8080/idp/profile/SAML2/POST/SSO");
        String rawSamlRequestString = docWriter.toString();
        byte[] rawSamlRequestBytes = rawSamlRequestString.getBytes("UTF-8");
        byte[] base64EncodedSamlRequestBytes = Base64.encode(rawSamlRequestBytes);
        String base64EncodedSamlRequestString = new String(base64EncodedSamlRequestBytes, "UTF-8");
//        String urlEncodedSamlRequest = URLEncoder.encode(base64EncodedSamlRequestString, "UTF-8");
        method.addParameter("SAMLRequest", base64EncodedSamlRequestString);
        int statusCode = client.executeMethod(method);
        String responseBody = method.getResponseBodyAsString();
        method.releaseConnection();
        System.out.println(responseBody);
    }

    private static Document createSignedRequest(Credential credential) throws org.opensaml.xml.signature.SignatureException, MarshallingException, ParserConfigurationException, KeyStoreException, CertificateEncodingException {

        // NOTE: For some reason this must be done before attempting to use the builder factory or else a NullPointerException will occur
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        SAMLObjectBuilder<AuthnRequest> requestBuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);

        AuthnRequest request = requestBuilder.buildObject();
        request.setID("MyRequestID" + (new DateTime()).toString());// Mark: generate a unique ID for each method (IDP will reject "replay" messages)
        request.setVersion(SAMLVersion.VERSION_20);
        request.setIssueInstant(new DateTime());
        request.setDestination("http://idp.example.org:8080/idp/profile/SAML2/POST/SSO");
        NameIDPolicy nameIDPolicy = ((SAMLObjectBuilder<NameIDPolicy>) builderFactory.getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME)).buildObject();
        nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        request.setNameIDPolicy(nameIDPolicy);

        Signature signature = (Signature) builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        KeyInfo keyInfo = (KeyInfo) builderFactory.getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME).buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);

        KeyStore ks = SamlReceiver.getKeyStore();
        X509Certificate certificate = (X509Certificate)ks.getCertificate("my_saml_signing_key");
        KeyInfoHelper.addPublicKey(keyInfo, certificate.getPublicKey());
        KeyInfoHelper.addCertificate(keyInfo, certificate);

        signature.setKeyInfo(keyInfo);
        request.setSignature(signature);

        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
//        issuer.setSPProvidedID("https://sp.example.org:8080/SAML2");
        issuer.setValue("https://sp.example.org:8080/SAML2");
        request.setIssuer(issuer);

// Get the subject builder based on the subject element name
//        SubjectBuilder builder = (SubjectBuilder) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
//
//// Create the subject
//        Subject subject = builder.buildObject();
//
//// Added an NameID and two SubjectConfirmation items - creation of these items is not shown
////        subject.setNameID(nameID);
////        subject.getSubjectConfirmations().add(subjectConfirmation1);
////        subject.getSubjectConfirmations().add(subjectConfirmation2);
//
//// Get the Subject marshaller
//        Marshaller marshaller = marshallerFactory.getMarshaller(subject);
//
//// Marshall the Subject
//        Element subjectElement = marshaller.marshall(subject);

//        MarshallerFactory marshallerFactory = new MarshallerFactory();
        Marshaller requestMarshaller = marshallerFactory.getMarshaller(AuthnRequest.DEFAULT_ELEMENT_NAME);

        DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document document = documentBuilder.newDocument();
        requestMarshaller.marshall(request, document);

        org.opensaml.xml.signature.Signer.signObject(signature);

        return document;
    }

}
