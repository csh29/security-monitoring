import java.beans.XMLDecoder;
import java.io.*;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.thoughtworks.xstream.XStream;

class DeserializationTest {
    Object bad(InputStream body) throws Exception {
        ObjectInputStream in = new ObjectInputStream(body);
        // ruleid: kisa-deserialization-object-input
        return in.readObject();
    }

    Object good(InputStream body) throws Exception {
        ObjectInputStream in = new ObjectInputStream(body);
        in.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.example.*;!*"));
        // ok: kisa-deserialization-object-input
        return in.readObject();
    }

    void polymorphic(InputStream body, ObjectMapper mapper, XStream xstream, String xml) {
        // ruleid: kisa-deserialization-polymorphic
        new XMLDecoder(body).readObject();
        // ruleid: kisa-deserialization-polymorphic
        mapper.enableDefaultTyping();
        // ruleid: kisa-deserialization-polymorphic
        xstream.fromXML(xml);
    }

    void xstreamSafe(XStream xstream, String xml) {
        xstream.allowTypes(new Class[]{Dto.class});
        // ok: kisa-deserialization-polymorphic
        xstream.fromXML(xml);
    }

    // ruleid: kisa-deserialization-polymorphic
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, property = "@class")
    static class Payload {
    }

    // ok: kisa-deserialization-polymorphic
    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
    static class Dto {
    }
}
