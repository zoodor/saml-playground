package com.example.helloworld.resources;

import com.sun.jersey.core.util.Base64;
import org.apache.commons.lang3.StringEscapeUtils;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.*;
import org.opensaml.xml.validation.ValidationException;
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
import java.io.IOException;
import java.net.URLDecoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

@Path("/saml-response-receiver")
@Produces(MediaType.TEXT_XML)
@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
public class SamlResponseReceiver {

    @POST
    public String postSaml(
            @FormParam("RelayState") String relayState,
            @FormParam("SAMLRequest") String samlRequest,
            @Context HttpServletRequest httpRequest) throws ConfigurationException, XMLParserException, UnmarshallingException, IOException, ParserConfigurationException, SAXException, MarshallingException, SignatureException, CertificateException, KeyStoreException, ValidationException, javax.security.cert.CertificateException {

        String urlDecodedSaml = URLDecoder.decode(samlRequest.replaceAll("\\r|\\n", ""), "UTF-8");
        byte[] samlBytes = Base64.decode(urlDecodedSaml);
        String base64DecodedSaml = new String(samlBytes, "UTF-8");
        String unescapedSaml = StringEscapeUtils.unescapeHtml4(base64DecodedSaml).replace("&apos;", "'");
        System.out.println(unescapedSaml);

        DefaultBootstrap.bootstrap();

        Response response = createResponseFromXmlString(unescapedSaml);

        return "";
    }

    private Response createResponseFromXmlString(String xmlString) throws ConfigurationException, ParserConfigurationException, SAXException, IOException, UnmarshallingException, ValidationException, CertificateException, KeyStoreException, javax.security.cert.CertificateException {

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
        Response response = (Response) unmarshaller.unmarshall(samlRootElement);

        Signature signature = response.getSignature();
        if (signature != null) {
            validateSignature(signature);
            System.out.println("Response signature successfully validated!");
        }

        List<Assertion> assertions = response.getAssertions();
        if (assertions.size() > 0) {
            Assertion assertion = assertions.get(0);
            Signature assertionSignature = assertion.getSignature();
            if (assertionSignature != null) {
                BasicX509Credential credential = new BasicX509Credential();

                CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
                KeyStore ks = SamlReceiver.getKeyStore();
                X509Certificate certificate =
                        (X509Certificate) certificateFactory.generateCertificate(new FileInputStream("/Users/mtaylor/Projects/IDA/cacert.pem"));

                validateSignature(assertionSignature, certificate);
                System.out.println("Assertion signature successfully validated!");
            }
        }

        return response;
    }

    private void validateSignature(Signature signature, X509Certificate certificate) throws CertificateException, ValidationException {

        BasicX509Credential credential = new BasicX509Credential();
        credential.setEntityCertificate(certificate);

        SignatureValidator signatureValidator = new SignatureValidator(credential);
        signatureValidator.validate(signature);
    }

    private void validateSignature(Signature signature) throws CertificateException, ValidationException {
        org.opensaml.xml.signature.X509Certificate openSamlCertificate = getCertificateFromSignature(signature);

        X509Certificate certificate = KeyInfoHelper.getCertificate(openSamlCertificate);

        validateSignature(signature, certificate);
    }

    private org.opensaml.xml.signature.X509Certificate getCertificateFromSignature(Signature signature) {
        KeyInfo keyInfo = signature.getKeyInfo();
        List<X509Data> x509Datas = keyInfo.getX509Datas();
        X509Data x509Data = x509Datas.get(0);
        return x509Data.getX509Certificates().get(0);
    }
}