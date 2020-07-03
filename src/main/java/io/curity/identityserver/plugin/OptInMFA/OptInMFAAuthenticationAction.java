/*
 *  Copyright 2020 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.curity.identityserver.plugin.OptInMFA;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.attribute.AccountAttributes;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes;
import se.curity.identityserver.sdk.attribute.MapAttributeValue;
import se.curity.identityserver.sdk.authentication.AuthenticatedSessions;
import se.curity.identityserver.sdk.authenticationaction.AuthenticationAction;
import se.curity.identityserver.sdk.authenticationaction.AuthenticationActionResult;
import se.curity.identityserver.sdk.errors.AuthenticatorNotConfiguredException;
import se.curity.identityserver.sdk.service.AccountManager;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptor;
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptorFactory;

import java.lang.invoke.MethodHandles;
import java.util.Map;

import static se.curity.identityserver.sdk.authenticationaction.completions.RequiredActionCompletion.AuthenticateUser.authenticate;
import static se.curity.identityserver.sdk.authenticationaction.completions.RequiredActionCompletion.PromptUser.prompt;

public final class OptInMFAAuthenticationAction implements AuthenticationAction
{
    public static final String ATTRIBUTE_PREFIX = "optinmfa:";
    public static final String CHOSEN_SECOND_FACTOR_ATTRIBUTE = ATTRIBUTE_PREFIX + "chosen-second-factor";
    public static final String IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE = ATTRIBUTE_PREFIX + "is-second-factor-chosen";
    public static final String AVAILABLE_SECOND_FACTORS_ATTRIBUTE = ATTRIBUTE_PREFIX + "second-factors";

    private static final Logger _logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private final AccountManager _accountManager;
    private final AuthenticatorDescriptorFactory _authenticatorDescriptorFactory;
    private final SessionManager _sessionManager;

    public OptInMFAAuthenticationAction(OptInMFAAuthenticationActionConfig configuration)
    {
        _accountManager = configuration.getAccountManager();
        _authenticatorDescriptorFactory = configuration.getAuthenticatorDescriptorFactory();
        _sessionManager = configuration.getSessionManager();
    }

    @Override
    public AuthenticationActionResult apply(AuthenticationAttributes authenticationAttributes,
                                            AuthenticatedSessions authenticatedSessions,
                                            String authenticationTransactionId,
                                            AuthenticatorDescriptor authenticatorDescriptor)
    {
        Attribute isSecondFactorChosenAttribute = _sessionManager.get(IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE);

        if (isSecondFactorChosenAttribute != null)
        {
            return handleActionWhenSecondFactorNotSet(authenticatedSessions, authenticationAttributes);
        }
        else
        {
            return handleActionWhenSecondFactorChosen(authenticationAttributes.getSubject());
        }
    }

    private AuthenticationActionResult handleActionWhenSecondFactorNotSet(AuthenticatedSessions authenticatedSessions, AuthenticationAttributes authenticationAttributes)
    {
        String secondFactorId = _sessionManager.get(CHOSEN_SECOND_FACTOR_ATTRIBUTE).getValueOfType(String.class);

        try
        {
            AuthenticatorDescriptor authenticator = _authenticatorDescriptorFactory.getAuthenticatorDescriptor(secondFactorId);

            if (authenticatedSessions.contains(authenticator.getAcr()))
            {
                _sessionManager.remove(IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE);
                _sessionManager.remove(CHOSEN_SECOND_FACTOR_ATTRIBUTE);

                return AuthenticationActionResult.successfulResult(authenticationAttributes);
            }

            return AuthenticationActionResult.pendingResult(authenticate(authenticator));
        }
        catch (AuthenticatorNotConfiguredException e)
        {
            _logger.info("Invalid authenticator chosen as second factor, or authenticator not configured: {}", secondFactorId);
            throw new IllegalStateException("Invalid authenticator");
        }
    }

    private AuthenticationActionResult handleActionWhenSecondFactorChosen(String subject)
    {
        AccountAttributes user = _accountManager.getByUserName(subject);

        Map<String, String> secondFactors = user.getOptionalValue("secondFactors", Map.class);

        if (secondFactors == null || secondFactors.isEmpty())
        {
            // TODO: allow to register first factor
            return AuthenticationActionResult.failedResult("secondFactor authenticators have to be set!");
        }

        _sessionManager.put(Attribute.of(AVAILABLE_SECOND_FACTORS_ATTRIBUTE, MapAttributeValue.of(secondFactors)));

        return AuthenticationActionResult.pendingResult(prompt());
    }
}
