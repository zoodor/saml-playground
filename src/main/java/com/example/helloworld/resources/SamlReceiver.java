package com.example.helloworld.resources;

import com.sun.jersey.core.util.Base64;
import org.apache.commons.lang3.StringEscapeUtils;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
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
import java.io.IOException;
import java.net.URLDecoder;

@Path("/saml-receiver")
@Produces(MediaType.TEXT_PLAIN)
@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
public class SamlReceiver {

    @POST
    public String postSaml(
            @FormParam("RelayState") String relayState,
            @FormParam("SAMLRequest") String samlRequest,
            @Context HttpServletRequest httpRequest) throws ConfigurationException, XMLParserException, UnmarshallingException, IOException, ParserConfigurationException, SAXException {

        String urlDecodedSaml = URLDecoder.decode(samlRequest.replaceAll("\\r|\\n", ""), "UTF-8");
        byte[] samlBytes = Base64.decode(urlDecodedSaml);
        String base64DecodedSaml = new String(samlBytes, "UTF-8");
        String unescapedSaml = StringEscapeUtils.unescapeHtml4(base64DecodedSaml).replace("&apos;", "'");
        System.out.println(unescapedSaml);

        AuthnRequest authenticationRequest = createAuthenticationRequestFromXmlString(unescapedSaml);

        return String.format("Relay state: %s, SAMLRequest: %s, request: %s", relayState, samlRequest, httpRequest);
    }

    private AuthnRequest createAuthenticationRequestFromXmlString(String xmlString) throws ConfigurationException, ParserConfigurationException, SAXException, IOException, UnmarshallingException {
        // Initialize the library
        DefaultBootstrap.bootstrap();

        // Get parser pool manager
        BasicParserPool ppMgr = new BasicParserPool();
        ppMgr.setNamespaceAware(true);

        DocumentBuilderFactory factory =
                DocumentBuilderFactory.newInstance ();
        factory.setNamespaceAware (true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Element samlRootElement = builder.parse(new ByteArrayInputStream(xmlString.getBytes())).getDocumentElement();

        // Get apropriate unmarshaller
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlRootElement);

        // Unmarshall using the document root element
        return (AuthnRequest) unmarshaller.unmarshall(samlRootElement);
    }
}