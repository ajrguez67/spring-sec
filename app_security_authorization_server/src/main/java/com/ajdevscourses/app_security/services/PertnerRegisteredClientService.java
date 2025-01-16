package com.ajdevscourses.app_security.services;

import com.ajdevscourses.app_security.repositories.PartnerRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Arrays;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class PertnerRegisteredClientService implements RegisteredClientRepository {

    private PartnerRepository partnerRepository;

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
        return null;
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {

        var partnerOpt = partnerRepository.findByClientId(clientId);

        return partnerOpt.map(
                partner -> {
                    var authorizationGrantTypes = Arrays.stream(partner.getGrantTypes().split(","))
                            .map(AuthorizationGrantType::new)
                            .toList();
                    var authenticationMethods = Arrays.stream(partner.getAuthenticationMethods().split(","))
                            .map(ClientAuthenticationMethod::new)
                            .toList();
                    var scopes = Arrays.stream(partner.getScopes().split(",")).toList();

                    return RegisteredClient
                            .withId(partner.getId().toString())
                            .clientId(partner.getClientId())
                            .clientSecret(partner.getClientSecret())
                            .clientName(partner.getClientName())
                            .redirectUri(partner.getRedirectUri())
                            .postLogoutRedirectUri(partner.getRedirectUriLogout())
                            .clientAuthenticationMethod(authenticationMethods.get(0))
                            .clientAuthenticationMethod(authenticationMethods.get(1))
                            .scope(scopes.get(0))
                            .scope(scopes.get(1))
                            .authorizationGrantType(authorizationGrantTypes.get(0))
                            .authorizationGrantType(authorizationGrantTypes.get(1))
                            .tokenSettings(this.tokenSettings())
                            .build();
        }).orElseThrow(() -> new BadCredentialsException("Client not exists"));
    }

    private TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(8))
                .build();
    }
}

