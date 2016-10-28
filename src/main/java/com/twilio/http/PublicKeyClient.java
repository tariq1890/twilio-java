package com.twilio.http;


import com.google.common.collect.Lists;
import com.twilio.Twilio;
import com.twilio.exception.ApiException;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import java.util.Map;

public class PublicKeyClient extends HttpClient {

    private static final int CONNECTION_TIMEOUT = 10000;
    private static final int SOCKET_TIMEOUT = 30500;

    private final org.apache.http.client.HttpClient client;

    public PublicKeyClient(String credentialSid, String publicKey) {
        RequestConfig config = RequestConfig.custom()
            .setConnectTimeout(CONNECTION_TIMEOUT)
            .setSocketTimeout(SOCKET_TIMEOUT)
            .build();

        Collection<Header> headers = Lists.<Header>newArrayList(
            new BasicHeader("X-Twilio-Client", "java-" + Twilio.VERSION),
            new BasicHeader(HttpHeaders.USER_AGENT, "twilio-java/" + Twilio.VERSION + " (" + Twilio.JAVA_VERSION + ")"),
            new BasicHeader(HttpHeaders.ACCEPT, "application/json"),
            new BasicHeader(HttpHeaders.ACCEPT_ENCODING, "utf-8")
        );

        client = HttpClientBuilder.create()
            .setConnectionManager(new PoolingHttpClientConnectionManager())
            .setDefaultRequestConfig(config)
            .setDefaultHeaders(headers)
            .setMaxConnPerRoute(10)
            .addInterceptorLast(new PublicKeyInterceptor(credentialSid, publicKey))
            .build();
    }

    @Override
    public Response makeRequest(Request request) {
        RequestBuilder builder = RequestBuilder.create(request.getMethod().toString())
            .setUri(request.constructURL().toString())
            .setVersion(HttpVersion.HTTP_1_1)
            .setCharset(StandardCharsets.UTF_8);

        if (request.requiresAuthentication()) {
            builder.addHeader(HttpHeaders.AUTHORIZATION, request.getAuthString());
        }

        HttpMethod method = request.getMethod();
        if (method == HttpMethod.POST) {
            builder.addHeader(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded");

            for (Map.Entry<String, List<String>> entry : request.getPostParams().entrySet()) {
                for (String value : entry.getValue()) {
                    builder.addParameter(entry.getKey(), value);
                }
            }
        }

        try {
            HttpResponse response = client.execute(builder.build());
            return new Response(
                response.getEntity() == null ? null : response.getEntity().getContent(),
                response.getStatusLine().getStatusCode()
            );
        } catch (IOException e) {
            throw new ApiException(e.getMessage());
        }
    }
}
