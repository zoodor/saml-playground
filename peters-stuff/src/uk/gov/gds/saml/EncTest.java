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
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.ChainingEncryptedKeyResolver;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.encryption.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.credential.CollectionCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoProvider;
import org.opensaml.xml.security.keyinfo.LocalKeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.provider.InlineX509DataProvider;
import org.opensaml.xml.security.keyinfo.provider.RSAKeyValueProvider;

import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static uk.gov.gds.saml.SamlFacade.KeySet.myKey;
import static uk.gov.gds.saml.SamlFacade.KeySet.myKey1;
import static uk.gov.gds.saml.SamlFacade.createFromXmlString;
import static uk.gov.gds.saml.SamlFacade.getCredential;
import static uk.gov.gds.saml.SamlFacade.getEncryptCredential;
import static uk.gov.gds.saml.SamlFacade.printDocument;

public class EncTest {

    @BeforeClass
    public static void init() throws ConfigurationException {
        DefaultBootstrap.bootstrap();
    }

    @Test
    public void encryptAssertion() throws ConfigurationException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, TransformerException, EncryptionException, MarshallingException {
        // The Assertion to be encrypted
        Assertion assertion = createAssertion("issuer", "ass01");

        // Assume this contains a recipient's RSA public key
        Credential keyEncryptionCredential = getCredential(myKey);

        EncryptionParameters encParams = new EncryptionParameters();
        encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

        KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
        kekParams.setEncryptionCredential(keyEncryptionCredential);
        kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        KeyInfoGeneratorFactory kigf =
                Configuration.getGlobalSecurityConfiguration()
                        .getKeyInfoGeneratorManager().getDefaultManager()
                        .getFactory(keyEncryptionCredential);
        kekParams.setKeyInfoGenerator(kigf.newInstance());

        Encrypter samlEncrypter = new Encrypter(encParams, kekParams);
        samlEncrypter.setKeyPlacement(Encrypter.KeyPlacement.PEER);

        EncryptedAssertion encryptedAssertion = samlEncrypter.encrypt(assertion);

        Configuration.getMarshallerFactory().getMarshaller(encryptedAssertion).marshall(encryptedAssertion);

        printDocument(encryptedAssertion.getDOM());
    }

    @Test
    public void encryptAssertionInResponse() throws ConfigurationException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, TransformerException, EncryptionException, MarshallingException {
        // The Assertion to be encrypted
        Response response = createResponse();

        // Assume this contains a recipient's RSA public key
        Credential keyEncryptionCredential = getCredential(myKey);

        EncryptionParameters encParams = new EncryptionParameters();
        encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

        KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
        kekParams.setEncryptionCredential(keyEncryptionCredential);
        kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        KeyInfoGeneratorFactory kigf =
                Configuration.getGlobalSecurityConfiguration()
                        .getKeyInfoGeneratorManager().getDefaultManager()
                        .getFactory(keyEncryptionCredential);
        kekParams.setKeyInfoGenerator(kigf.newInstance());

        Encrypter samlEncrypter = new Encrypter(encParams, kekParams);
        samlEncrypter.setKeyPlacement(Encrypter.KeyPlacement.PEER);

        Assertion assertion = response.getAssertions().get(0);
        response.getEncryptedAssertions().add(samlEncrypter.encrypt(assertion));
        response.getAssertions().remove(assertion);

        Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);

        printDocument(response.getDOM());
    }

    @Test
    public void decrypt() throws ConfigurationException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, TransformerException, EncryptionException, MarshallingException, XMLParserException, UnmarshallingException, DecryptionException {
// Collection of local credentials, where each contains
// a private key that corresponds to a public key that may
// have been used by other parties for encryption
        List<Credential> localCredentials = Arrays.asList(getEncryptCredential(myKey));

        CollectionCredentialResolver localCredResolver = new CollectionCredentialResolver(localCredentials);

// Support EncryptedKey/KeyInfo containing decryption key hints via
// KeyValue/RSAKeyValue and X509Data/X509Certificate
        List<KeyInfoProvider> kiProviders = new ArrayList<KeyInfoProvider>();
        kiProviders.add(new RSAKeyValueProvider());
        kiProviders.add(new InlineX509DataProvider());

// Resolves local credentials by using information in the EncryptedKey/KeyInfo to query the supplied
// local credential resolver.
        KeyInfoCredentialResolver kekResolver = new LocalKeyInfoCredentialResolver(kiProviders, localCredResolver);

// Supports resolution of EncryptedKeys by 3 common placement mechanisms
        ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver();
        encryptedKeyResolver.getResolverChain().add(new InlineEncryptedKeyResolver());
        encryptedKeyResolver.getResolverChain().add(new EncryptedElementTypeEncryptedKeyResolver());
        encryptedKeyResolver.getResolverChain().add(new SimpleRetrievalMethodEncryptedKeyResolver());

        Decrypter decrypter =
                new Decrypter(null, kekResolver, encryptedKeyResolver);

        EncryptedAssertion encryptedAssertion = createFromXmlString(encAssertion);

        Assertion assertion = decrypter.decrypt(encryptedAssertion);

        printDocument(assertion.getDOM());
    }

    @Test
    public void decryptResponse() throws ConfigurationException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, TransformerException, EncryptionException, MarshallingException, XMLParserException, UnmarshallingException, DecryptionException {
// Collection of local credentials, where each contains
// a private key that corresponds to a public key that may
// have been used by other parties for encryption
        List<Credential> localCredentials = Arrays.asList(getEncryptCredential( myKey));

        CollectionCredentialResolver localCredResolver = new CollectionCredentialResolver(localCredentials);

// Support EncryptedKey/KeyInfo containing decryption key hints via
// KeyValue/RSAKeyValue and X509Data/X509Certificate
        List<KeyInfoProvider> kiProviders = new ArrayList<KeyInfoProvider>();
        kiProviders.add(new RSAKeyValueProvider());
        kiProviders.add(new InlineX509DataProvider());

// Resolves local credentials by using information in the EncryptedKey/KeyInfo to query the supplied
// local credential resolver.
        KeyInfoCredentialResolver kekResolver = new LocalKeyInfoCredentialResolver(kiProviders, localCredResolver);

// Supports resolution of EncryptedKeys by 3 common placement mechanisms
        ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver();
        encryptedKeyResolver.getResolverChain().add(new InlineEncryptedKeyResolver());
        encryptedKeyResolver.getResolverChain().add(new EncryptedElementTypeEncryptedKeyResolver());
        encryptedKeyResolver.getResolverChain().add(new SimpleRetrievalMethodEncryptedKeyResolver());

        Decrypter decrypter =
                new Decrypter(null, kekResolver, encryptedKeyResolver);

        Response response = createFromXmlString(encResponse);

        EncryptedAssertion encryptedAssertion = response.getEncryptedAssertions().get(0);
        response.getAssertions().add(decrypter.decrypt(encryptedAssertion));
        response.getEncryptedAssertions().remove(encryptedAssertion);

        Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);

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

    private Response createResponse() throws ConfigurationException {
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        SAMLObjectBuilder<Response> builder = (SAMLObjectBuilder<Response>) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);

        Response response = builder.buildObject();
        response.setID("res");
        response.getAssertions().add(createAssertion("sdfghjkl", "ass01"));
//        response.getAssertions().add(createAssertion("sdfghjkl", "ass02"));
//        response.getAssertions().add(createAssertion("sdfghjkl", "ass02"));
        return response;
    }

    private static String encAssertion = "<saml2:EncryptedAssertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"_e7813fb4df8bc01eddc6d406d513d8b8\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:RetrievalMethod Type=\"http://www.w3.org/2001/04/xmlenc#EncryptedKey\" URI=\"#_649d8fab5b443c9cdc44d5d3efb5f062\"/></ds:KeyInfo><xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:CipherValue>zDUdhvGWcxgohzm2rqXjO2S+Foj4qz19O/D5cOadpuvqq76ANDQ7k2rUtNAAIO89mH2nOWbc6MHUtNzGm5Mjp80I8xusvL3ZT6keBgpYO/9NAXwUnQ/nsWwdBokrBS0oNjR7RhbInQhz4yh030M+LpnIaRNC4qW7m2LrpskjaQsfnXHiQ/8gvIotaAt0VYt4seiofIbeqJ+4XV44+VywKmOjWG8eXAV6/NpwwflCNtUC3iyFIXbbPP7osr4QgiAOinVsTPhH799D0mUfqJHoFhtfhdHHI4FCU5WkEMFvOrGMnWN8x9CJA8qv91wIO1Rl9oGX/4mLjW9JFGJYSxRe/K/C0Fx2vtmu9R9YXuoduson4qcBrubBmH/asyoiwNnVLo+B3513C/Gsex5d1dafZg==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData><xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"_649d8fab5b443c9cdc44d5d3efb5f062\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><ds:DigestMethod xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/></xenc:EncryptionMethod><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>yz5+OTwPO6bk52BJAQzmOeh+j86cOfvbqzDxzTrqxB8XDfBOQZvahaFi1JTzMbXicqn89qFQnsCFFbzWBwVO5hdHbp0BcSQuHotxIeWOK8ogyr5Uvz9DVsL734QAnk7o1Vu/DKW3FTYOObFOFoUA4ZEj4EFAQlc94rw275+Ffgs=</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo><xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:CipherValue>wV8+Ppt4FPKhtqprJ/sp8/mTKKyKo8oGObiRn5slT7X+AWC2nENsLl9f6mQsyalRdlRBMSMW1JPqHOiSOQ7eqpVc+V9WQTf3C0cjGIwbKxvUtUMYeGo/FsNkJsscPeljpYnifJJaUG01q63jGDXFVzOyUXa3gfVwbmixn70DRhk=</xenc:CipherValue></xenc:CipherData><xenc:ReferenceList><xenc:DataReference URI=\"#_e7813fb4df8bc01eddc6d406d513d8b8\"/></xenc:ReferenceList></xenc:EncryptedKey></saml2:EncryptedAssertion>";

    private static String encResponse = "<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"res\" Version=\"2.0\"><saml2:EncryptedAssertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"_4e23fb8ef786504ad6bda97e33183fd7\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:RetrievalMethod Type=\"http://www.w3.org/2001/04/xmlenc#EncryptedKey\" URI=\"#_702fbec8c5cad7b7c2c23d277a2618ff\"/></ds:KeyInfo><xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:CipherValue>hxPs6lodfQHIBF5GUwRJrAUVKVXeL+Z9Bgn1k2jvwe2R8/ezasYFIdcZoIGP1HD9Vl3O45COW3RX6cPo1QGGTZx6cMDj/p4FWL+C59gkl8MKa+Sfp3rUu/p4tzp7gCHrmmldTkOFLyZsfBHPsuNDQNlFFVYX5WgKwjI7xfsqLv8lzhEjYV5yt6zs8uhh/bnXDtx1aiBgkhTnYh29wo8PJkP+ssxMZnKxU6tJjXdBtw7RT13iDE6QSuOKCjObXj24nAl/3h3vgdl1S4CwbKvhREsxwsgjCWkZmnhzvnhMRXaJR529ZDnidyS6lNT2z4Y+BYxawZQo3TRUR0Ojoczl4iFq/BUvPEj5xBm8lLkyTka/SJbrDUX3dAGZy1CUT+lsuxQNNjcMyYTbkvHsu4Siyk2j2/F9OA+1tI2yPBZOYtw=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData><xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"_702fbec8c5cad7b7c2c23d277a2618ff\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><ds:DigestMethod xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/></xenc:EncryptionMethod><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>yz5+OTwPO6bk52BJAQzmOeh+j86cOfvbqzDxzTrqxB8XDfBOQZvahaFi1JTzMbXicqn89qFQnsCFFbzWBwVO5hdHbp0BcSQuHotxIeWOK8ogyr5Uvz9DVsL734QAnk7o1Vu/DKW3FTYOObFOFoUA4ZEj4EFAQlc94rw275+Ffgs=</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo><xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:CipherValue>eDHYJpb5soLZRhTn2uP5zDTXtwZ0Lw2fjKBgVmMNZaxEodCqldIQPOLLuX1RxrLZKWcBJhnaVWZXb4kmedLxU9Qd/6+Bwxad+IZw96yw46026avVfK2eEogUpLMZQkdZvlnAYXWwjLVO9pJDDpkGfswW3B6piQPvapJENGBzsHI=</xenc:CipherValue></xenc:CipherData><xenc:ReferenceList><xenc:DataReference URI=\"#_4e23fb8ef786504ad6bda97e33183fd7\"/></xenc:ReferenceList></xenc:EncryptedKey></saml2:EncryptedAssertion></saml2p:Response>";
}
