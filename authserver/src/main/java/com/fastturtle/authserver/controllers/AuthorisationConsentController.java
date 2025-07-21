package com.fastturtle.authserver.controllers;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.*;

@Controller
public class AuthorisationConsentController {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    public AuthorisationConsentController(RegisteredClientRepository registeredClientRepository,
                                          OAuth2AuthorizationConsentService authorizationConsentService) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationConsentService = authorizationConsentService;
    }

    @GetMapping(value = "/oauth2/consent")
    public String consent(Principal principal, Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) String state) {

        // Remove scopes that were already approved
        Set<String> scopesToApprove = new HashSet<>();
        Set<String> previouslyApprovedScopes = new HashSet<>();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        OAuth2AuthorizationConsent currentAuthorizationConsent =
                this.authorizationConsentService.findById(registeredClient.getId(), principal.getName());
        Set<String> authorizedScopes;
        if (currentAuthorizationConsent != null) {
            authorizedScopes = currentAuthorizationConsent.getScopes();
        } else {
            authorizedScopes = Collections.emptySet();
        }
        for (String requestedScope : StringUtils.delimitedListToStringArray(scope, " ")) {
            if (authorizedScopes.contains(requestedScope)) {
                previouslyApprovedScopes.add(requestedScope);
            } else {
                if(!"openid".equals(requestedScope)) {
                    scopesToApprove.add(requestedScope);
                }
            }
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("state", state);
        model.addAttribute("scopes", withDescription(scopesToApprove));
        model.addAttribute("previouslyApprovedScopes", withDescription(previouslyApprovedScopes));
        model.addAttribute("principalName", principal.getName());

        return "consent";
    }

    private static Set<ScopeWithDescription> withDescription(Set<String> scopes) {
        Set<ScopeWithDescription> scopeWithDescriptions = new HashSet<>();
        for (String scope : scopes) {
            scopeWithDescriptions.add(new ScopeWithDescription(scope));

        }
        return scopeWithDescriptions;
    }

    public static class ScopeWithDescription {
//        private static final String DEFAULT_DESCRIPTION = "UNKNOWN SCOPE - We cannot provide information about this permission, use caution when granting this.";
        private static final String DEFAULT_DESCRIPTION = "";
        private static final Map<String, String> scopeDescriptions = new HashMap<>();
        static {
            scopeDescriptions.put(
                    "access.coders",
                    "Access the coders data"
            );
            scopeDescriptions.put(
                    "access.designers",
                    "Access the designers data"
            );
            scopeDescriptions.put(
                    "access.books",
                    "Access the books data"
            );
        }

        public final String scope;
        public final String description;

        ScopeWithDescription(String scope) {
            this.scope = scope;
            this.description = scopeDescriptions.getOrDefault(scope, DEFAULT_DESCRIPTION);
        }
    }
}