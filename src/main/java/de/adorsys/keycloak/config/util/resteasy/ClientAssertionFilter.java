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

package de.adorsys.keycloak.config.util.resteasy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;

public class ClientAssertionFilter implements ClientRequestFilter {
    public static final String CLIENT_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static final String TOKEN_ENDPOINT_SUFFIX = "/protocol/openid-connect/token";

    private final Path assertionFile;

    public ClientAssertionFilter(Path assertionFile) {
        this.assertionFile = assertionFile;
    }

    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {
        if (!isTokenRequest(requestContext)) {
            return;
        }

        Object entity = requestContext.getEntity();
        if (!(entity instanceof MultivaluedMap<?, ?>)) {
            throw new IOException("Unexpected Keycloak token request entity: "
                    + (entity == null ? "null" : entity.getClass().getName()));
        }

        @SuppressWarnings("unchecked")
        MultivaluedMap<String, String> form = (MultivaluedMap<String, String>) entity;
        form.remove("client_id");
        form.putSingle("client_assertion_type", CLIENT_ASSERTION_TYPE);
        form.putSingle("client_assertion", readAssertion());
        requestContext.getHeaders().remove(HttpHeaders.AUTHORIZATION);
    }

    private boolean isTokenRequest(ClientRequestContext requestContext) {
        return HttpMethod.POST.equals(requestContext.getMethod())
                && requestContext.getUri().getPath().endsWith(TOKEN_ENDPOINT_SUFFIX);
    }

    private String readAssertion() throws IOException {
        String assertion = Files.readString(assertionFile).trim();
        if (assertion.isEmpty()) {
            throw new IOException("Client assertion file is empty: " + assertionFile);
        }
        return assertion;
    }
}
