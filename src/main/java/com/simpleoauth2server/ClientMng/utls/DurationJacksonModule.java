package com.simpleoauth2server.ClientMng.utls;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.time.Duration;

public class DurationJacksonModule extends SimpleModule {

    public DurationJacksonModule() {
        addSerializer(Duration.class, new DurationSerializer());
        addDeserializer(Duration.class, new DurationDeserializer());
    }

    static class DurationSerializer extends StdSerializer<Duration> {
        protected DurationSerializer() {
            super(Duration.class);
        }

        @Override
        public void serialize(Duration value, JsonGenerator gen, SerializerProvider provider) throws IOException {
            gen.writeString(value.toString());
        }
    }

    static class DurationDeserializer extends StdDeserializer<Duration> {
        protected DurationDeserializer() {
            super(Duration.class);
        }

        @Override
        public Duration deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            JsonNode node = p.getCodec().readTree(p);

            // Handle string format (ISO-8601 like "PT30M")
            if (node.isTextual()) {
                try {
                    return Duration.parse(node.asText());
                } catch (Exception e) {
                    // Log the error but continue with a fallback
                    System.err.println("Error parsing duration: " + node.asText() + " - " + e.getMessage());
                }
            }

            // Handle numeric format (seconds)
            if (node.isNumber()) {
                return Duration.ofSeconds(node.asLong());
            }

            // Return a default value if parsing fails
            return Duration.ofMinutes(30);
        }
    }
}