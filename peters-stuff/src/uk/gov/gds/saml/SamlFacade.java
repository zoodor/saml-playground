package uk.gov.gds.saml;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityTestHelper;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.StaticCredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.trust.TrustEngine;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.w3c.dom.Document;
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
import java.io.RandomAccessFile;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SamlFacade {

    public static enum KeySet {
        myKey, myKey1
    }

    public static <T extends SAMLObject> T createFromXmlString(String s) throws XMLParserException, UnmarshallingException {
        // Get parser pool manager
        BasicParserPool ppMgr = new BasicParserPool();
        ppMgr.setNamespaceAware(true);

        // Parse metadata file
        Document doc = ppMgr.parse(new StringReader(s));
        Element rootElement = doc.getDocumentElement();

        // Get apropriate unmarshaller
        Unmarshaller unmarshaller = org.opensaml.xml.Configuration.getUnmarshallerFactory().getUnmarshaller(rootElement);

        return (T) unmarshaller.unmarshall(rootElement);
    }

    /**
     * I don't know why, but this matters
     * @param keySet
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws IOException
     */
    public static Credential getEncryptCredential(KeySet keySet) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        BasicCredential credential = (BasicCredential) getCredential(keySet);
        credential.setUsageType(UsageType.ENCRYPTION);
        return credential;
    }

    public static Credential getCredential(KeySet keySet) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        BasicCredential credential = new BasicCredential();
        PublicKey publicKey = getPublicKey(keySet.name());
        credential.setPublicKey(publicKey);

        PrivateKey privateKey = getPrivateKey(keySet.name());

        credential.setPrivateKey(privateKey);
        credential.setUsageType(UsageType.SIGNING);
        return credential;
    }


    public static Signature createSignature(KeySet keySet) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, org.opensaml.xml.security.SecurityException {
        Credential signingCredential = getCredential(SamlFacade.KeySet.valueOf(keySet.name()));

        Signature signature = (Signature) Configuration.getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(signingCredential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        return signature;
    }

    private static PublicKey getPublicKey(String keyName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        RandomAccessFile raf = new RandomAccessFile(keyName + ".pub", "r");
        byte[] buf = new byte[(int)raf.length()];
        raf.readFully(buf);
        raf.close();
        KeySpec keySpec = new X509EncodedKeySpec(buf);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private static PrivateKey getPrivateKey(String keyName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        RandomAccessFile raf = new RandomAccessFile(keyName + ".pk8", "r");
        byte[] buf = new byte[(int)raf.length()];
        raf.readFully(buf);
        raf.close();
        KeySpec keySpec = new PKCS8EncodedKeySpec(buf);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public static CriteriaSet createCriteriaSet() {
        return new CriteriaSet(new EntityIDCriteria("urn:example.org:issuer"));
    }

    public static TrustEngine createTrustEngine(KeySet keySet) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        CredentialResolver credentialResolver = new StaticCredentialResolver(getCredential(keySet));
        KeyInfoCredentialResolver keyInfoCredentialResolver = SecurityTestHelper.buildBasicInlineKeyInfoResolver();
        return new ExplicitKeySignatureTrustEngine(credentialResolver, keyInfoCredentialResolver);
    }

    public static SignatureValidator createSignatureValidator(KeySet keySet) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        return new SignatureValidator(getCredential(keySet));
    }

    public static void printDocument(Element element) throws IOException, TransformerException {
        printDocument(element, System.out);
    }

    public static void printDocument(Element element, OutputStream out) throws IOException, TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(OutputKeys.INDENT, "no");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

        transformer.transform(new DOMSource(element),
                new StreamResult(new OutputStreamWriter(out, "UTF-8")));
    }
}
