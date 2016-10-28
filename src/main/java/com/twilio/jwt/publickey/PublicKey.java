package com.twilio.jwt.publickey;

import com.google.common.base.Charsets;
import com.google.common.base.Joiner;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.io.CharStreams;
import com.twilio.jwt.Jwt;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpRequest;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


public class PublicKey extends Jwt {

    private static final HashFunction HASH_FUNCTION = Hashing.sha256();

    private final String method;
    private final String uri;
    private final String queryString;
    private final Header[] headers;
    private final Collection<String> signedHeaders;
    private final String requestBody;

    private PublicKey(Builder b) {
        super(
            SignatureAlgorithm.HS256,
            b.privateKey,
            b.credentialSid,
            new Date(new Date().getTime() + b.ttl * 1000)
        );
        this.method = b.method;
        this.uri = b.uri;
        this.queryString = b.queryString;
        this.headers = b.headers;
        this.signedHeaders = b.signedHeaders;
        this.requestBody = b.requestBody;
    }

    @Override
    public Map<String, Object> getHeaders() {
        return Collections.emptyMap();
    }

    @Override
    public Map<String, Object> getClaims() {
        Map<String, Object> paylaod = new HashMap<>();

        String hashedHeaders = HASH_FUNCTION.hashString(Joiner.on(";").join(signedHeaders), Charsets.UTF_8).toString();
        String encodedHeaders = String.valueOf(Hex.encodeHex(hashedHeaders.getBytes(), true));
        paylaod.put("hrh", encodedHeaders);

        StringBuilder signature = new StringBuilder();
        signature.append(method).append("\n");
        signature.append(uri).append("\n");
        signature.append(queryString).append("\n");

        for (Header header: headers) {
            if (signedHeaders.contains(header.getName())) {
                signature.append(header.getName().toLowerCase().trim())
                    .append(":")
                    .append(header.getValue().trim())
                    .append("\n");
            }
        }
        signature.append("\n");
        signature.append(encodedHeaders).append("\n");

        String hashedPayload = HASH_FUNCTION.hashString(requestBody, Charsets.UTF_8).toString();
        signature.append(Hex.encodeHex(hashedPayload.getBytes(), true)).append("\n");

        paylaod.put("rqh", signature.toString());

        return paylaod;
    }

    public static PublicKey fromHttpRequest(
        String credentialSid,
        String privateKey,
        HttpRequest request,
        Collection<String> signedHeaders
    ) throws IOException {
        Builder builder = new Builder(credentialSid, privateKey);

        String method = request.getRequestLine().getMethod();
        builder.method(method);

        String uri = request.getRequestLine().getUri();
        if (uri.contains("?")) {
            String[] uriParts = uri.split("\\?");
            builder.uri(uriParts[0]);
            builder.queryString(uriParts[1]);
        } else {
            builder.uri(uri);
        }

        builder.headers(request.getAllHeaders());
        builder.signedHeaders(signedHeaders);

        if ("POST".equals(method.toUpperCase())) {
            HttpEntity entity = ((HttpEntityEnclosingRequest)request).getEntity();
            builder.requestBody(CharStreams.toString(new InputStreamReader(entity.getContent(), Charsets.UTF_8)));
        }

        return builder.build();
    }

    public static class Builder {

        private String credentialSid;
        private String privateKey;
        private String method;
        private String uri;
        private String queryString = "";
        private Header[] headers;
        private Collection<String> signedHeaders = Collections.emptyList();
        private String requestBody = "";
        private int ttl = 3600;

        public Builder(String credentialSid, String privateKey) {
            this.credentialSid = credentialSid;
            this.privateKey = privateKey;
        }

        public Builder method(String method) {
            this.method = method;
            return this;
        }

        public Builder uri(String uri) {
            this.uri = uri;
            return this;
        }

        public Builder queryString(String queryString) {
            this.queryString = queryString;
            return this;
        }

        public Builder headers(Header[] headers) {
            this.headers = headers;
            return this;
        }

        public Builder signedHeaders(Collection<String> signedHeaders) {
            this.signedHeaders = signedHeaders;
            return this;
        }

        public Builder requestBody(String requestBody) {
            this.requestBody = requestBody;
            return this;
        }

        public Builder ttl(int ttl) {
            this.ttl = ttl;
            return this;
        }

        public PublicKey build() {
            return new PublicKey(this);
        }
    }

}
