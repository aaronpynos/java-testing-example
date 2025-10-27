package net.allocation.astras.web.APIDOCS.controllers;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.io.IOUtils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.jndi.support.SimpleJndiBeanFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

import static java.util.Objects.requireNonNull;

/**
 * This controller proxies requests to the path /api-docs to the running sidecar container with swagger ui.
 */
@RestController
public class ApidocsProxyController {
    private RestTemplate restTemplate;
    private String proxiedUrl;

    @PostConstruct
    public void init() {
        SimpleJndiBeanFactory jndiBeanFactory = new SimpleJndiBeanFactory();
        proxiedUrl = requireNonNull((String) jndiBeanFactory.getBean("api/swagger-ui"),
                "JNDI entry 'api/swagger-ui' must be configured");

        // Ensure the proxiedUrl ends with a slash for consistent path joining
        if (!proxiedUrl.endsWith("/")) {
            proxiedUrl += "/";
        }

        restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new ResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(URI uri, HttpMethod method, ClientHttpResponse response) {
                // Response is forwarded to the client without any error handling.
            }
        });
    }

    /**
     * The only method that is listening to requests to api-docs and forwards it to the configured swagger server.
     * The response is returned to the browser.
     *
     * @param request the request
     * @return a response entity with the content of the proxied url.
     * @throws IOException
     */
    @RequestMapping("/**")
    public ResponseEntity route(HttpServletRequest request) throws IOException {
        String body = IOUtils.toString(request.getReader());

        // 1. Get the part of the path provided by the user
        String userPath = request.getRequestURI().substring(request.getContextPath().length() + "/api-docs".length());
        try {
            // 2. Safely build and normalize the target URI
            // This resolves path traversal sequences like /../
            URI targetUri = UriComponentsBuilder.fromUriString(proxiedUrl)
                    .path(userPath)
                    .query(request.getQueryString())
                    .build(true) // Set to true to encode the template variables
                    .toUri()
                    .normalize();

            // 3. VALIDATE: Ensure the normalized URL is still within the intended scope
            URI baseUri = new URI(proxiedUrl);

            // Basic checks: host and path must remain under the configured base, scheme must be http/https,
            // and the port must match the configured base port to avoid SSRF to other services.
            String targetHost = targetUri.getHost();
            String baseHost = baseUri.getHost();

            if (targetHost == null || baseHost == null) {
                return new ResponseEntity<>("Invalid path specified".getBytes(), HttpStatus.BAD_REQUEST);
            }

            int basePort = baseUri.getPort();
            int targetPort = targetUri.getPort();

            // Resolve default ports if not explicitly provided
            if (basePort == -1) {
                basePort = "https".equalsIgnoreCase(baseUri.getScheme()) ? 443 : 80;
            }
            if (targetPort == -1) {
                targetPort = "https".equalsIgnoreCase(targetUri.getScheme()) ? 443 : 80;
            }

            boolean schemeAllowed = "http".equalsIgnoreCase(targetUri.getScheme()) || "https".equalsIgnoreCase(targetUri.getScheme());
            boolean sameHost = targetHost.equalsIgnoreCase(baseHost);
            boolean samePort = targetPort == basePort;
            boolean pathAllowed = targetUri.getPath() != null && targetUri.getPath().startsWith(baseUri.getPath());

            if (!schemeAllowed || !sameHost || !samePort || !pathAllowed) {
                // If the path escaped the base URL or scheme/port/host differ, treat as malicious.
                return new ResponseEntity<>("Invalid path specified".getBytes(), HttpStatus.BAD_REQUEST);
            }

            // 4. Use the safe, validated URI to make the request
            ResponseEntity<byte[]> response = restTemplate.exchange(targetUri,
                    HttpMethod.valueOf(request.getMethod()),
                    new HttpEntity<>(body),
                    byte[].class);

            HttpHeaders headers = new HttpHeaders();
            for (String name : response.getHeaders().keySet()) {
                if ("Content-Security-Policy".equals(name)) {
                    headers.add(name, "frame-ancestors 'self'");
                } else {
                    headers.addAll(name, Objects.requireNonNull(response.getHeaders().get(name)));
                }
            }
            return new ResponseEntity<>(response.getBody(), headers, response.getStatusCode());
        } catch (final HttpClientErrorException e) {
            return new ResponseEntity<>(e.getResponseBodyAsByteArray(), e.getResponseHeaders(), e.getStatusCode());
        } catch (IllegalArgumentException e) {
            // Catches potential errors from invalid characters in the URI
            return new ResponseEntity<>("Invalid URI".getBytes(), HttpStatus.BAD_REQUEST);
        } catch (URISyntaxException e) {
            return new ResponseEntity<>("Invalid URI".getBytes(), HttpStatus.BAD_REQUEST);
        }
    }
}