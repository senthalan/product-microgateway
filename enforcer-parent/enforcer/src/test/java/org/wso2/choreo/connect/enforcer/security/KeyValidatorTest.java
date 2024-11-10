package org.wso2.choreo.connect.enforcer.security;

import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.wso2.choreo.connect.enforcer.commons.model.ResourceConfig;
import org.wso2.choreo.connect.enforcer.config.ConfigHolder;
import org.wso2.choreo.connect.enforcer.dto.APIKeyValidationInfoDTO;
import org.wso2.choreo.connect.enforcer.exception.EnforcerException;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ConfigHolder.class})
@PowerMockIgnore("javax.management.*")
class KeyValidatorTest {

    @Test
    void validateNoTokenScopeOAuthSecuritySchemeWithNoScope() throws EnforcerException {

        TokenValidationContext validationContext = createValidationContext(Collections.EMPTY_SET,
                Collections.EMPTY_MAP);

        boolean isValid = KeyValidator.validateScopes(validationContext);
        assert isValid;
    }

    @Test
    void validateNoTokenScopeOAuthSecurityScheme() throws EnforcerException {

        TokenValidationContext validationContext = createValidationContext(Collections.EMPTY_SET,
                Map.of("oauth2", List.of("scope1")));

        boolean isValid = KeyValidator.validateScopes(validationContext);
        assert !isValid;
    }

    @Test
    void validateWithTokenScopeOAuthSecurityScheme() throws EnforcerException {

        TokenValidationContext validationContext = createValidationContext(Set.of("scope1"),
                Map.of("oauth2", List.of("scope1")));

        boolean isValid = KeyValidator.validateScopes(validationContext);
        assert isValid;
    }

    @Test
    void validateNoTokenScopeBothScheme() throws EnforcerException {

        TokenValidationContext validationContext = createValidationContext(Collections.EMPTY_SET,
                Map.of("oauth2", Collections.emptyList(), "apikey", Collections.emptyList()));

        boolean isValid = KeyValidator.validateScopes(validationContext);
        assert isValid;
    }

    @Test
    void validateWithTokenScopeBothSecuritySchemeWithSameScope() throws EnforcerException {

        TokenValidationContext validationContext = createValidationContext(Set.of("scope1"),
                Map.of("oauth2", List.of("scope1"), "apikey",  List.of("scope1")));

        boolean isValid = KeyValidator.validateScopes(validationContext);
        assert isValid;
    }

    @Test
    void validateNoTokenScopeBothSchemeWithSameScope() throws EnforcerException {

        TokenValidationContext validationContext = createValidationContext(Collections.EMPTY_SET,
                Map.of("oauth2", List.of("scope1"), "apikey", List.of("scope1")));

        boolean isValid = KeyValidator.validateScopes(validationContext);
        assert !isValid;
    }

    @Test
    void validateNoTokenScopeBothSchemeOneWithNoScope() throws EnforcerException {

        TokenValidationContext validationContext = createValidationContext(Collections.EMPTY_SET,
                Map.of("oauth2", List.of("scope1"), "apikey", Collections.emptyList()));

        boolean isValid = KeyValidator.validateScopes(validationContext);
        assert !isValid;
    }


    private static TokenValidationContext createValidationContext(Set<String> tokenScopes,
                                                                  Map<String, List<String>> securitySchemas
                                                                  ) {

        TokenValidationContext validationContext = new TokenValidationContext();
        validationContext.setAccessToken("testAccessToken");

        APIKeyValidationInfoDTO validationInfoDTO = new APIKeyValidationInfoDTO();
        validationInfoDTO.setScopes(tokenScopes);
        validationContext.setValidationInfoDTO(validationInfoDTO);

        ResourceConfig resourceConfig = new ResourceConfig();
        resourceConfig.setSecuritySchemas(securitySchemas);
        validationContext.setMatchingResourceConfig(resourceConfig);
        return validationContext;
    }
}