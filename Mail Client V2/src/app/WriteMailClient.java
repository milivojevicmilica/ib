package app;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.lang.model.element.Element;
import javax.mail.internet.MimeMessage;
import javax.sound.midi.Receiver;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;

import com.google.api.services.gmail.Gmail;
import model.keystore.KeyStoreReader;
import model.mailclient.MailBody;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import xml.signature.SignEnveloped;
import support.MailHelper;
import support.MailWritter;
import support.XML;


public class WriteMailClient extends MailClient {

	
	private static final String KEY_STORE_FILE="./data/usera.jks";
	private static final String KEY_STORE_FILE1="./data/userb.jks";
	private static final String KEY_STORE_PASSA= "usera";
	private static final String KEY_STORE_ALIASA = "usera";
	private static final String KEY_STORE_PASS_FOR_PRIVATE_KEYA = "usera";
	private static final String KEY_STORE_ALIASB= "userb";
	private static final String KEY_STORE_PASS_FOR_PRIVATE_KEYB = "userb";
	private static final String OUT_FILE = "./data/mail.xml";
	private static final String OUT_FILE2 = "./data/mail_signed.xml";
	
	public static void main(String[] args) {
		
       
    		try {
    			Gmail service = getGmailService();

    			System.out.println("Insert a reciever:");
    			BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
    			String reciever = reader.readLine();

    			System.out.println("Insert a subject:");
    			String subject = reader.readLine();

    			System.out.println("Insert body:");
    			String body = reader.readLine();
    			
    			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
    			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
    			Document doc = docBuilder.newDocument();
    			org.w3c.dom.Element rootElement = doc.createElement("mail");

    			org.w3c.dom.Element subjectElement = doc.createElement("subject");
    			subjectElement.setTextContent(subject);
    			rootElement.appendChild(subjectElement);
    			
    			org.w3c.dom.Element bodyElement = doc.createElement("body");
    			bodyElement.setTextContent(body);
    			rootElement.appendChild(bodyElement);
    			
    			
    			
    			doc.appendChild(rootElement);
    			
    			
    			SignEnveloped.signDocument(doc);
    			
    			
    			SecretKey secretKey = KeyStoreReader.generateSessionKey();
    			PublicKey publicKey = KeyStoreReader.getPublicKey("./data/userb.jks", "userb", "userb", "userb");

    			XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_128);
    			xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);

    			XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
    			keyCipher.init(XMLCipher.WRAP_MODE, publicKey);
    		
    			org.apache.xml.security.encryption.EncryptedKey encryptedKey = keyCipher.encryptKey(doc, secretKey);
    			System.out.println("Kriptovan tajni kljuc: " + encryptedKey);
    			
    			KeyInfo keyInfo = new KeyInfo(doc);
    			keyInfo.addKeyName("Kriptovani tajni kljuc");
    			keyInfo.add(encryptedKey);		
    		
    			EncryptedData encryptedData = xmlCipher.getEncryptedData();
    			encryptedData.setKeyInfo(keyInfo);
    			
    			xmlCipher.doFinal(doc,rootElement, true);

    			String encryptedXml = XML.DocumentToString(doc);
    			System.out.println("Mail posle enkripcije: " + encryptedXml);

    			MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever,"Encrypted text", encryptedXml);
    			MailWritter.sendMessage(service, "me", mimeMessage);
    			saveDocument(doc, OUT_FILE);
    		}
    			
    			
    		catch(Exception e) {
    				e.printStackTrace();
    			
    		}

   
    			
    		
    		
    		
    	}public static void saveDocument(Document doc, String fileName) {
    		try {
    			File outFile = new File(fileName);
    			FileOutputStream f = new FileOutputStream(outFile);

    			TransformerFactory factory = TransformerFactory.newInstance();
    			Transformer transformer = factory.newTransformer();

    			DOMSource source = new DOMSource(doc);
    			StreamResult result = new StreamResult(f);

    			transformer.transform(source, result);

    			f.close();

    		} catch (Exception e) {
    			e.printStackTrace();
    		}
	}
}
