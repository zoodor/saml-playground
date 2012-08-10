package uk.gov.gds.saml;

import org.joda.time.DateTime;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.w3c.dom.Element;

import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static uk.gov.gds.saml.SamlFacade.KeySet.myKey;
import static uk.gov.gds.saml.SamlFacade.getCredential;
import static uk.gov.gds.saml.SamlFacade.printDocument;

public class SmatTest {

    @BeforeClass
    public static void init() throws ConfigurationException {
        DefaultBootstrap.bootstrap();
    }

    @Test
    public void shouldDoStuff() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, ConfigurationException, MarshallingException, TransformerException, SecurityException, SignatureException {
        Credential signingCredential = getCredential(myKey);
        Response response = createResponse();

        Signature signature = (Signature) Configuration.getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(signingCredential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        response.setSignature(signature);

        Element marshall = Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);
        Signer.signObject(signature);
        printDocument(marshall);
    }

    private Assertion createAssertion() throws ConfigurationException {
        // Get the builder factory
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

        // Get the assertion builder based on the assertion element name
        SAMLObjectBuilder<Assertion> builder = (SAMLObjectBuilder<Assertion>) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue("sdfghjkl");

        // Create the assertion
        Assertion assertion = builder.buildObject();
        assertion.setIssueInstant(new DateTime());
        assertion.setID("ass01");
        assertion.setIssuer(issuer);
        return assertion;
    }

    private Response createResponse () throws ConfigurationException {
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        SAMLObjectBuilder<Response> builder = (SAMLObjectBuilder<Response>) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);

        Response response = builder.buildObject();
        response.getAssertions().add(createAssertion());
        return response;
    }
}
