package support;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public class XML {
		
		public static String DocumentToString(Document doc) throws TransformerException {
			TransformerFactory transformFactory = TransformerFactory.newInstance();
			Transformer transformer = transformFactory.newTransformer();
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(doc), new StreamResult(writer));
			String output = writer.getBuffer().toString().replaceAll("\n|\r", "");

			return output;
		}
		
		public static Document StringToDocument(String xmlAsString){
			DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();  
			documentFactory.setNamespaceAware(true);
			DocumentBuilder builder;  
			Document doc = null;
			try {  
			    builder = documentFactory.newDocumentBuilder();  
			    doc = builder.parse(new InputSource(new StringReader(xmlAsString)));  
			} catch (Exception e) {  
			    e.printStackTrace();  
			} 
			return doc;
		}
	

}
