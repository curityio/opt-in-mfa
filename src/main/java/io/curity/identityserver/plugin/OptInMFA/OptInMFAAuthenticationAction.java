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

import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.NonEmptyList;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.AccountAttributes;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes;
import se.curity.identityserver.sdk.attribute.ListAttributeValue;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.CONFIRM_SCRATCH_CODES;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.FIRST_CHOICE_OF_SECOND_FACTOR;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.FIRST_SECOND_FACTOR_REGISTERED;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.NO_SECOND_FACTOR_CHOSEN;
import static se.curity.identityserver.sdk.authenticationaction.completions.RequiredActionCompletion.AuthenticateUser.authenticate;
import static se.curity.identityserver.sdk.authenticationaction.completions.RequiredActionCompletion.PromptUser.prompt;
import static se.curity.identityserver.sdk.authenticationaction.completions.RequiredActionCompletion.RegisterUser.register;

public final class OptInMFAAuthenticationAction implements AuthenticationAction
{
    public static final String ATTRIBUTE_PREFIX = "optinmfa:";
    public static final String OPT_IN_MFA_STATE = ATTRIBUTE_PREFIX + "opt-in-mfa-state";
    public static final String CHOSEN_SECOND_FACTOR_ATTRIBUTE = ATTRIBUTE_PREFIX + "chosen-second-factor";
    public static final String CHOSEN_SECOND_FACTOR_NAME = ATTRIBUTE_PREFIX + "chosen-second-factor-name";
    public static final String AVAILABLE_SECOND_FACTORS_ATTRIBUTE = ATTRIBUTE_PREFIX + "second-factors";
    public static final String REMEMBER_CHOICE_COOKIE_NAME = "rememberSecondFactorChoice";
    public static final String SCRATCH_CODES = ATTRIBUTE_PREFIX + "scratch-codes";

    private static final Logger _logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    public static final String SECOND_FACTORS = "secondFactors";

    private final AccountManager _accountManager;
    private final AuthenticatorDescriptorFactory _authenticatorDescriptorFactory;
    private final SessionManager _sessionManager;
    private final Map<String, String> _availableSecondFactors;
    private final ScratchCodeGenerator _scratchCodeGenerator;

    public OptInMFAAuthenticationAction(OptInMFAAuthenticationActionConfig configuration, ScratchCodeGenerator scratchCodeGenerator)
    {
        _accountManager = configuration.getAccountManager();
        _authenticatorDescriptorFactory = configuration.getAuthenticatorDescriptorFactory();
        _sessionManager = configuration.getSessionManager();
        _availableSecondFactors = new HashMap<>(configuration.availableAuthenticators().size());
        configuration.availableAuthenticators().forEach((factor) -> _availableSecondFactors.put(factor, factor));
        _scratchCodeGenerator = scratchCodeGenerator;
    }

    @Override
    public AuthenticationActionResult apply(AuthenticationAttributes authenticationAttributes,
                                            AuthenticatedSessions authenticatedSessions,
                                            String authenticationTransactionId,
                                            AuthenticatorDescriptor authenticatorDescriptor)
    {
        @Nullable Attribute optInMFAState = _sessionManager.get(OPT_IN_MFA_STATE);

        OptInMFAState processState = NO_SECOND_FACTOR_CHOSEN;
        if (optInMFAState == null) {
            _sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, NO_SECOND_FACTOR_CHOSEN));
        } else {
            processState = OptInMFAState.valueOf(optInMFAState.getValueOfType(String.class));
        }

        switch (processState) {
            case SECOND_FACTOR_CHOSEN: return handleActionWhenSecondFactorChosen(authenticatedSessions, authenticationAttributes);
            case FIRST_SECOND_FACTOR_CHOSEN: return handleFirstChoiceOfSecondFactor();
            case FIRST_SECOND_FACTOR_REGISTERED: return handleContinueFirstRegistrationOfSecondFactor(authenticationAttributes);
            case SCRATCH_CODES_CONFIRMED: return handleScratchCodesConfirmed(authenticationAttributes);
            default: return handleActionWhenSecondFactorNotSet(authenticationAttributes, authenticatedSessions);
        }
    }

    private AuthenticationActionResult handleContinueFirstRegistrationOfSecondFactor(AuthenticationAttributes authenticationAttributes)
    {
        String chosenSecondFactor = _sessionManager.remove(CHOSEN_SECOND_FACTOR_ATTRIBUTE).getValueOfType(String.class);
        String chosenSecondFactorName = _sessionManager.remove(CHOSEN_SECOND_FACTOR_NAME).getValueOfType(String.class);
        List<String> scratchCodes = _scratchCodeGenerator.generateScratchCodes();

        AccountAttributes user = _accountManager.getByUserName(authenticationAttributes.getSubject());
        AccountAttributes modifiedUser = AccountAttributes.of(user)
                .with(Attribute.of(SECOND_FACTORS, MapAttributeValue.of(Collections.singletonMap(chosenSecondFactorName, chosenSecondFactor))))
                .with(Attribute.of("secondFactorCodes", ListAttributeValue.of(scratchCodes.stream().map(DigestUtils::sha256Hex).collect(Collectors.toList()))));

        _accountManager.updateAccount(modifiedUser);

        _sessionManager.put(Attribute.of(SCRATCH_CODES, ListAttributeValue.of(scratchCodes)));
        _sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, CONFIRM_SCRATCH_CODES));

        return AuthenticationActionResult.pendingResult(prompt());
    }

    private AuthenticationActionResult handleScratchCodesConfirmed(AuthenticationAttributes authenticationAttributes)
    {
        _sessionManager.remove(OPT_IN_MFA_STATE);

        return AuthenticationActionResult.successfulResult(authenticationAttributes);
    }

    private AuthenticationActionResult handleFirstChoiceOfSecondFactor()
    {
        String secondFactorAcr = _sessionManager.remove(CHOSEN_SECOND_FACTOR_ATTRIBUTE).getValueOfType(String.class);

        try
        {
            NonEmptyList<AuthenticatorDescriptor> authenticators = _authenticatorDescriptorFactory.getAuthenticatorDescriptors(secondFactorAcr);
            _sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_REGISTERED));
            //TODO - the path should not be required, it's a bug.
            //TODO - what if the chosen authenticator requires a path?
            return AuthenticationActionResult.pendingResult(register(authenticators.getFirst(), true, ""));
        }
        catch (AuthenticatorNotConfiguredException e)
        {
            _logger.info("Invalid authenticator chosen as second factor, or authenticator not configured: {}", secondFactorAcr);
            throw new IllegalStateException("Invalid authenticator chosen.");
        }
    }

    private AuthenticationActionResult handleActionWhenSecondFactorChosen(AuthenticatedSessions authenticatedSessions, AuthenticationAttributes authenticationAttributes)
    {
        String secondFactorAcr = _sessionManager.remove(CHOSEN_SECOND_FACTOR_ATTRIBUTE).getValueOfType(String.class);

        if (authenticatedSessions.contains(secondFactorAcr))
        {
            return AuthenticationActionResult.successfulResult(authenticationAttributes);
        }

        try
        {
            NonEmptyList<AuthenticatorDescriptor> authenticators = _authenticatorDescriptorFactory.getAuthenticatorDescriptors(secondFactorAcr);
            return AuthenticationActionResult.pendingResult(authenticate(authenticators.getFirst()));
        }
        catch (AuthenticatorNotConfiguredException e)
        {
            _logger.info("Invalid authenticator chosen as second factor, or authenticator not configured: {}", secondFactorAcr);
            throw new IllegalStateException("Invalid authenticator chosen.");
        }
    }

    private AuthenticationActionResult handleActionWhenSecondFactorNotSet(AuthenticationAttributes authenticationAttributes, AuthenticatedSessions authenticatedSessions)
    {
        AccountAttributes user = _accountManager.getByUserName(authenticationAttributes.getSubject());

        Map<String, String> secondFactors = user.getOptionalValue(SECOND_FACTORS, Map.class);

        if (secondFactors == null || secondFactors.isEmpty())
        {
            _sessionManager.put(Attribute.of(AVAILABLE_SECOND_FACTORS_ATTRIBUTE, MapAttributeValue.of(_availableSecondFactors)));
            _sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, FIRST_CHOICE_OF_SECOND_FACTOR));
        }
        else
        {
            if (secondFactors.values().stream().anyMatch(authenticatedSessions::contains))
            {
                return AuthenticationActionResult.successfulResult(authenticationAttributes);
            }

            _sessionManager.put(Attribute.of(AVAILABLE_SECOND_FACTORS_ATTRIBUTE, MapAttributeValue.of(secondFactors)));
        }

        return AuthenticationActionResult.pendingResult(prompt());
    }
}
