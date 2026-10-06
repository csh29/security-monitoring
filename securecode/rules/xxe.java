import javax.xml.XMLConstants;
import javax.xml.parsers.*;
import javax.xml.stream.XMLInputFactory;
import javax.xml.transform.TransformerFactory;

class XxeTest {
    void bad() throws Exception {
        // ruleid: kisa-xxe-parser
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder();
    }

    void badSax() throws Exception {
        // ruleid: kisa-xxe-parser
        SAXParserFactory spf = SAXParserFactory.newInstance();
    }

    void badStax() {
        // ruleid: kisa-xxe-parser
        XMLInputFactory xif = XMLInputFactory.newInstance();
    }

    void good() throws Exception {
        // ok: kisa-xxe-parser
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.newDocumentBuilder();
    }

    void goodStax() {
        // ok: kisa-xxe-parser
        XMLInputFactory xif = XMLInputFactory.newInstance();
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    }

    void goodTransformer() {
        // ok: kisa-xxe-parser
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    }
}
