/*-
 * ---license-start
 * keycloak-config-cli
 * ---
 * Copyright (C) 2017 - 2026 adorsys GmbH & Co. KG @ https://adorsys.com
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package de.adorsys.keycloak.config.provider;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import de.adorsys.keycloak.config.properties.KeycloakConfigProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KeycloakProviderClientAssertionTest {
    private static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    @TempDir
    Path temporaryDirectory;

    @Test
    void rereadsProjectedTokenForInitialGrantAndRefresh() throws Exception {
        List<TokenRequest> requests = new ArrayList<>();
        try (TokenEndpoint endpoint = new TokenEndpoint(requests)) {
            Path tokenFile = temporaryDirectory.resolve("keycloak-token");
            Files.writeString(tokenFile, "projected-token-one\n");

            try (KeycloakProvider provider = createProvider(endpoint.url(), "", tokenFile.toString())) {
                provider.getInstance();
                Files.writeString(tokenFile, "projected-token-two\n");
                provider.refreshToken();
            }
        }

        assertEquals(2, requests.size());
        assertEquals("client_credentials", requests.get(0).form().get("grant_type"));
        assertEquals("projected-token-one", requests.get(0).form().get("client_assertion"));
        assertEquals(ASSERTION_TYPE, requests.get(0).form().get("client_assertion_type"));
        assertFalse(requests.get(0).form().containsKey("client_id"));
        assertNull(requests.get(0).authorization());

        assertEquals("refresh_token", requests.get(1).form().get("grant_type"));
        assertEquals("projected-token-two", requests.get(1).form().get("client_assertion"));
        assertEquals(ASSERTION_TYPE, requests.get(1).form().get("client_assertion_type"));
        assertFalse(requests.get(1).form().containsKey("client_id"));
        assertNull(requests.get(1).authorization());
    }

    @Test
    void preservesClientSecretAuthenticationWhenAssertionFileIsNotConfigured() throws Exception {
        List<TokenRequest> requests = new ArrayList<>();
        try (TokenEndpoint endpoint = new TokenEndpoint(requests);
                KeycloakProvider provider = createProvider(endpoint.url(), "existing-secret", "")) {
            provider.getInstance();
        }

        assertEquals(1, requests.size());
        String credentials = Base64.getEncoder()
                .encodeToString("existing-client:existing-secret".getBytes(StandardCharsets.UTF_8));
        assertEquals("Basic " + credentials, requests.get(0).authorization());
        assertFalse(requests.get(0).form().containsKey("client_assertion"));
        assertFalse(requests.get(0).form().containsKey("client_assertion_type"));
    }

    private KeycloakProvider createProvider(String url, String clientSecret, String assertionFile) throws Exception {
        KeycloakConfigProperties properties = mock(KeycloakConfigProperties.class);
        when(properties.getUrl()).thenReturn(url);
        when(properties.getLoginRealm()).thenReturn("appmana");
        when(properties.getClientId()).thenReturn("existing-client");
        when(properties.getGrantType()).thenReturn("client_credentials");
        when(properties.getClientSecret()).thenReturn(clientSecret);
        when(properties.getClientAssertionFile()).thenReturn(assertionFile);
        when(properties.getUser()).thenReturn("");
        when(properties.getPassword()).thenReturn("");
        when(properties.getVersion()).thenReturn("26.5.5");
        when(properties.isSkipServerInfo()).thenReturn(true);
        when(properties.isSslVerify()).thenReturn(true);
        when(properties.getConnectTimeout()).thenReturn(Duration.ofSeconds(2));
        when(properties.getReadTimeout()).thenReturn(Duration.ofSeconds(2));
        when(properties.getAvailabilityCheck()).thenReturn(
                new KeycloakConfigProperties.KeycloakAvailabilityCheck(false, Duration.ofSeconds(1),
                        Duration.ofMillis(10)));

        Constructor<KeycloakProvider> constructor = KeycloakProvider.class
                .getDeclaredConstructor(KeycloakConfigProperties.class);
        constructor.setAccessible(true);
        return constructor.newInstance(properties);
    }

    private static Map<String, String> decodeForm(String encodedForm) {
        Map<String, String> form = new LinkedHashMap<>();
        for (String entry : encodedForm.split("&")) {
            String[] pair = entry.split("=", 2);
            String key = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
            String value = pair.length == 2 ? URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : "";
            form.put(key, value);
        }
        return form;
    }

    private record TokenRequest(Map<String, String> form, String authorization) {
    }

    private static final class TokenEndpoint implements AutoCloseable {
        private final HttpServer server;

        private TokenEndpoint(List<TokenRequest> requests) throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/realms/appmana/protocol/openid-connect/token",
                    exchange -> handleTokenRequest(exchange, requests));
            server.createContext("/realms/appmana/protocol/openid-connect/logout",
                    exchange -> {
                        exchange.sendResponseHeaders(204, -1);
                        exchange.close();
                    });
            server.start();
        }

        private String url() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        private static void handleTokenRequest(HttpExchange exchange, List<TokenRequest> requests)
                throws IOException {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            requests.add(new TokenRequest(decodeForm(body), exchange.getRequestHeaders().getFirst("Authorization")));

            byte[] response = ("{\"access_token\":\"access-token\",\"expires_in\":60,"
                    + "\"refresh_expires_in\":60,\"refresh_token\":\"refresh-token\","
                    + "\"token_type\":\"Bearer\"}").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
