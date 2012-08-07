package com.example.helloworld.resources;

import com.sun.jersey.core.util.Base64;
import org.apache.commons.lang3.StringEscapeUtils;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.*;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.*;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URLDecoder;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

@Path("/saml-receiver")
@Produces(MediaType.TEXT_XML)
@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
public class SamlReceiver {

    @POST
    public Document postSaml(
            @FormParam("RelayState") String relayState,
            @FormParam("SAMLRequest") String samlRequest,
            @Context HttpServletRequest httpRequest) throws ConfigurationException, XMLParserException, UnmarshallingException, IOException, ParserConfigurationException, SAXException, MarshallingException, SignatureException, CertificateException, KeyStoreException, ValidationException {

        String urlDecodedSaml = URLDecoder.decode(samlRequest.replaceAll("\\r|\\n", ""), "UTF-8");
        byte[] samlBytes = Base64.decode(urlDecodedSaml);
        String base64DecodedSaml = new String(samlBytes, "UTF-8");
        String unescapedSaml = StringEscapeUtils.unescapeHtml4(base64DecodedSaml).replace("&apos;", "'");
        System.out.println(unescapedSaml);

        DefaultBootstrap.bootstrap();

        Credential credential = getCredential();
        Document responseDocument = createSignedResponse(credential);

        AuthnRequest authenticationRequest = createAuthenticationRequestFromXmlString(unescapedSaml);

        return responseDocument;

//        return String.format("Relay state: %s, SAMLRequest: %s, request: %s", relayState, samlRequest, httpRequest);
    }

    private Credential getCredential() {

        Logger logger = LoggerFactory.getLogger(SamlReceiver.class);
        Signature signature = null;
        String certificateAliasName = "<saml-signing-key-alias>";
        KeyStore ks = getKeyStore();

        // Get Private Key Entry From Certificate
        KeyStore.PrivateKeyEntry pkEntry = null;
        try {
            pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(certificateAliasName, new KeyStore.PasswordProtection("<saml-signing-key-password>".toCharArray()));
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to Get Private Entry From the keystore", e);
        } catch (UnrecoverableEntryException e) {
            logger.error("Failed to Get Private Entry From the keystore", e);
        } catch (KeyStoreException e) {
            logger.error("Failed to Get Private Entry From the keystore", e);
        }
        PrivateKey pk = pkEntry.getPrivateKey();

        X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();
        BasicX509Credential credential = new BasicX509Credential();
        credential.setEntityCertificate(certificate);
        credential.setPrivateKey(pk);

        logger.info("Private Key" + pk.toString());

        return credential;
    }

//    private Credential getServiceProviderCredential() {
//
//    }

    private KeyStore getKeyStore() {
        Logger logger = LoggerFactory.getLogger(SamlReceiver.class);
        String passwordString = "<saml-keystore-password>";
        String fileName = "<path-to-saml-keystore-file>";


        KeyStore ks = null;
        FileInputStream fis = null;
        char[] password = passwordString.toCharArray();

        // Get Default Instance of KeyStore
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            logger.error("Error while Intializing Keystore", e);
        }

        // Read Ketstore as file Input Stream
        try {
            fis = new FileInputStream(fileName);
        } catch (FileNotFoundException e) {
            logger.error("Unable to found KeyStore with the given keystoere name ::" + fileName, e);
        }

        // Load KeyStore
        try {
            ks.load(fis, password);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to Load the KeyStore:: ", e);
        } catch (CertificateException e) {
            logger.error("Failed to Load the KeyStore:: ", e);
        } catch (IOException e) {
            logger.error("Failed to Load the KeyStore:: ", e);
        }

        // Close InputFileStream
        try {
            fis.close();
        } catch (IOException e) {
            logger.error("Failed to close file stream:: ", e);
        }
        return ks;
    }

    private Document createSignedResponse(Credential credential) throws org.opensaml.xml.signature.SignatureException, MarshallingException, ParserConfigurationException, KeyStoreException, CertificateEncodingException {

        // NOTE: For some reason this must be done before attempting to use the builder factory or else a NullPointerException will occur
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);

        Response response = responseBuilder.buildObject();
        response.setID("MyResponseID");
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssueInstant(new DateTime());
//        response.setDestination("MyDestination");

        SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");
        SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
        Status status = statusBuilder.buildObject();
        status.setStatusCode(statusCode);
        response.setStatus(status);

        Signature signature = (Signature) builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        KeyInfo keyInfo = (KeyInfo) builderFactory.getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME).buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);

        KeyStore ks = getKeyStore();
        X509Certificate certificate = (X509Certificate)ks.getCertificate("<saml-signing-key-alias>");
//        credential.setEntityCertificate(certificate);
        KeyInfoHelper.addPublicKey(keyInfo, certificate.getPublicKey());
        KeyInfoHelper.addCertificate(keyInfo, certificate);

        signature.setKeyInfo(keyInfo);
        response.setSignature(signature);

//        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
//        Issuer issuer = issuerBuilder.buildObject();
//        issuer.setSPProvidedID("https://sp.example.com/SAML2");
//        response.setIssuer(issuer);

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
        Marshaller responseMarshaller = marshallerFactory.getMarshaller(Response.DEFAULT_ELEMENT_NAME);


        DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document document = documentBuilder.newDocument();
        Element marshalledResponse = responseMarshaller.marshall(response, document);

        org.opensaml.xml.signature.Signer.signObject(signature);

        return document;
    }

    private AuthnRequest createAuthenticationRequestFromXmlString(String xmlString) throws ConfigurationException, ParserConfigurationException, SAXException, IOException, UnmarshallingException, ValidationException, CertificateException {
        // Initialize the library
//        DefaultBootstrap.bootstrap();

        // Get parser pool manager
        BasicParserPool ppMgr = new BasicParserPool();
        ppMgr.setNamespaceAware(true);

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware (true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Element samlRootElement = builder.parse(new ByteArrayInputStream(xmlString.getBytes())).getDocumentElement();

        // Get apropriate unmarshaller
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlRootElement);


        // Unmarshall using the document root element
        AuthnRequest request = (AuthnRequest) unmarshaller.unmarshall(samlRootElement);

        Signature signature = request.getSignature();
        KeyInfo keyInfo = signature.getKeyInfo();
        List<X509Data> x509Datas = keyInfo.getX509Datas();
        X509Data x509Data = x509Datas.get(0);
        BasicX509Credential credential = new BasicX509Credential();
        X509Certificate certificateFromSignature = KeyInfoHelper.getCertificate(x509Data.getX509Certificates().get(0));
        credential.setEntityCertificate(certificateFromSignature);
//        Credential credential = getCredential();

        SignatureValidator signatureValidator = new SignatureValidator(credential);
        signatureValidator.validate(signature);

        return request;
    }
}