package model.keystore;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;





public class KeyStoreReader {


	/**
	 * Klasa koja sluzi za citanje iz KeyStore fajla
	 *
	 */
		/**
		 * Metoda sluzi za ucitavanje KeyStore-a sa zadate putanje
		 * 
		 * @param keyStoreFilePath - putanja do KeyStore fajla
		 * @param password - sifra za otvaranje KeyStore fajla
		 * 
		 * @return Instanca KeyStore objekta
		 */
	
		
		private Certificate cert = null;

		public IssuerData readKeyStore(String keyStoreFile, String alias, char[] password, char[] keyPass) throws ParseException {
			IssuerData issuer = null;
			try {
				KeyStore ks = KeyStore.getInstance("JKS", "SUN");
				
				BufferedInputStream in = new BufferedInputStream(
						new FileInputStream(keyStoreFile));
				ks.load(in, password);
				
				System.out.println("Cita se Sertifikat...");
				System.out.println("Ucitani sertifikat:");
				
				cert = ks.getCertificate(alias);
				System.out.println(cert);
				
				PrivateKey privKey = (PrivateKey) ks.getKey(alias, keyPass);

				X500Name issuerName = new JcaX509CertificateHolder(
						(X509Certificate) cert).getSubject();
				issuer = new IssuerData(privKey, issuerName);
				

			} catch (KeyStoreException e) {
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (UnrecoverableKeyException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
			return issuer;

		}
		
		public PublicKey readPublicKey() {
			return cert.getPublicKey();
		}
		public static PrivateKey getPrivateKey(String path, String alias, String password, String keyPass) {
			KeyStoreReader ksr = new KeyStoreReader();
			try {
				return ksr.readKeyStore(path, alias, password.toCharArray(), keyPass.toCharArray()).getPrivateKey();
			} catch (ParseException e) {
				System.out.println("ERROR: PublicKey = NULL");
				return null;
			}		
		}
		
		public static PublicKey getPublicKey(String path, String alias, String password, String keyPass) {
			KeyStoreReader ksr = new KeyStoreReader();
			try {
				ksr.readKeyStore(path, alias, password.toCharArray(), keyPass.toCharArray());
				return ksr.readPublicKey();
			} catch (ParseException e) {
				System.out.println("ERROR: PublicKey = NULL");
				return null;
			}
		}
		
		public static SecretKey generateSessionKey() {
			KeyGenerator keyGen;
			try {
				keyGen = KeyGenerator.getInstance("AES");
				return keyGen.generateKey();
			} catch (NoSuchAlgorithmException e) {
				return null;
			} 
			
		}
	}

