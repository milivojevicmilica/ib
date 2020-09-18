package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import model.keystore.KeyStoreReader;
import model.mailclient.MailBody;
import support.MailHelper;
import support.MailReader;
import support.XML;
import util.Base64;
import util.GzipUtil;
import xml.signature.SignEnveloped;

public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	
	private static KeyStoreReader keyStoreReader= new KeyStoreReader();
	private static final String KEY_STORE_FILE1="./data/userb.jks";
	private static final String KEY_STORE_PASS_FOR_PRIVATE_KEYB = "userb";
	private static final String KEY_STORE_ALIASB= "userb";
	private static final String KEY_STORE_PASSB= "userb";
	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	static {
        Security.addProvider(new BouncyCastleProvider());
        org.apache.xml.security.Init.init();
	}
	
	public static void main(String[] args) throws Throwable {
        
		 Gmail service = getGmailService();
	        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
	        
	        String user = "me";
	        String query = "is:unread label:INBOX";
	        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
	        for(int i=0; i<messages.size(); i++) {
	        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
	        	
	        	MimeMessage mimeMessage;
				try {
					mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
					
					System.out.println("\n Message number " + i);
					System.out.println("From: " + mimeMessage.getHeader("From", null));
					System.out.println("Subject: " + mimeMessage.getSubject());
					System.out.println("Body: " + MailHelper.getText(mimeMessage));
					System.out.println("\n");
					
					mimeMessages.add(mimeMessage);
		        
				} catch (MessagingException e) {
					e.printStackTrace();
				}	
	        }
	        
	        System.out.println("Select a message to decrypt:");
	        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		        
		    String answerStr = reader.readLine();
		    Integer answer = Integer.parseInt(answerStr);
		    
			MimeMessage chosenMessage = mimeMessages.get(answer);
			String xmlAsString = MailHelper.getText(chosenMessage);
			Document doc = XML.StringToDocument(xmlAsString);
			
			
			PrivateKey prvateKey = KeyStoreReader.getPrivateKey("./data/userb.jks", "userb", "userb", "userb");
			XMLCipher xmlCipher = XMLCipher.getInstance();
			xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
			
			xmlCipher.setKEK(prvateKey);
			
			NodeList encDataList = doc.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData");
			Element encData = (Element) encDataList.item(0);
			
			
			xmlCipher.doFinal(doc, encData); 
			System.out.println("Verified: " + SignEnveloped.verifySignature(doc));
			
			String msg = doc.getElementsByTagName("body").item(0).getTextContent();
			String title = doc.getElementsByTagName("subject").item(0).getTextContent();
			
			System.out.println("Body text: " + (msg.split("\n"))[0]);

			System.out.println("Title: " + (title.split("\n"))[0]);
			
	}
}
