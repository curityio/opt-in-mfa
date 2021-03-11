/*
 *  Copyright 2021 Curity AB
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
package io.curity.identityserver.plugin.OptInMFA.handler;

import io.curity.identityserver.plugin.OptInMFA.OptInMFAState;
import io.curity.identityserver.plugin.OptInMFA.exception.MissingSecondFactorParameterException;
import io.curity.identityserver.plugin.OptInMFA.model.AuthenticatorModel;
import io.curity.identityserver.plugin.OptInMFA.model.ChooseAnotherFactorRequestModel;
import io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationActionConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.NonEmptyList;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.AccountAttributes;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.authenticationaction.completions.ActionCompletionRequestHandler;
import se.curity.identityserver.sdk.authenticationaction.completions.ActionCompletionResult;
import se.curity.identityserver.sdk.errors.AuthenticatorNotConfiguredException;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.service.AccountManager;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptor;
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptorFactory;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;
import se.curity.identityserver.sdk.web.ResponseModel;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.ANOTHER_SECOND_FACTOR_ATTRIBUTE;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.ANOTHER_SECOND_FACTOR_NAME;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.OPT_IN_MFA_STATE;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.SECOND_FACTORS;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.SUBJECT;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.ANOTHER_NEW_SECOND_FACTOR_CHOSEN;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.NO_SECOND_FACTOR_CHOSEN;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.SECOND_FACTOR_CHOSEN_TO_DELETE;
import static io.curity.identityserver.plugin.OptInMFA.model.AuthenticatorModel.of;

public final class OptInMFARegisterAnotherFactorHandler implements ActionCompletionRequestHandler<ChooseAnotherFactorRequestModel>
{
    private final SessionManager _sessionManager;
    private final ExceptionFactory _exceptionFactory;
    private final AccountManager _accountManager;
    private final AuthenticatorDescriptorFactory _descriptorFactory;
    private final List<String> _availableSecondFactors;
    private final Optional<String> _smsAuthenticatorACR;
    private final Optional<String> _emailAuthenticatorACR;

    public static final Logger _logger = LoggerFactory.getLogger(OptInMFARegisterAnotherFactorHandler.class);

    public OptInMFARegisterAnotherFactorHandler(AuthenticatorDescriptorFactory descriptorFactory, OptInMFAAuthenticationActionConfig configuration, ExceptionFactory exceptionFactory)
    {
        _descriptorFactory = descriptorFactory;
        _sessionManager = configuration.getSessionManager();
        _exceptionFactory = exceptionFactory;
        _accountManager = configuration.getAccountManager();
        _availableSecondFactors = configuration.getAvailableAuthenticators();
        _smsAuthenticatorACR = configuration.getSMSAuthenticatorACR();
        _emailAuthenticatorACR = configuration.getEmailAuthenticatorACR();
    }

    @Override
    public Optional<ActionCompletionResult> get(ChooseAnotherFactorRequestModel request, Response response)
    {
        Attribute subjectAttribute = _sessionManager.get(SUBJECT);
        if (subjectAttribute == null) {
            _logger.info("No information in session about the pre-authenticated user.");
            throw _exceptionFactory.badRequestException(ErrorCode.INVALID_SERVER_STATE);
        }

        String subject = subjectAttribute.getValueOfType(String.class);

        AccountAttributes user = _accountManager.getByUserName(subject);

        Map<String, String> currentSecondFactorAcrs = user.get(SECOND_FACTORS).getValueOfType(Map.class);
        List<AuthenticatorModel> currentSecondFactors = new ArrayList<>(currentSecondFactorAcrs.size());

        currentSecondFactorAcrs.forEach((name, acr) -> {
            @Nullable AuthenticatorModel model = getAuthenticatorModel(acr, name);
            if (model != null) {
                currentSecondFactors.add(model);
            }
        });

        response.putViewData("currentAuthenticators", currentSecondFactors, Response.ResponseModelScope.NOT_FAILURE);

        List<AuthenticatorModel> availableSecondFactors = new ArrayList<>(_availableSecondFactors.size());

        _availableSecondFactors.forEach(acr -> {
            @Nullable AuthenticatorModel model = getAuthenticatorModel(acr, acr);
            if (model != null)
            {
                availableSecondFactors.add(model);
            }
        });

        _smsAuthenticatorACR.ifPresent(smsAuthenticatorACR -> {
            if (!currentSecondFactorAcrs.containsValue(smsAuthenticatorACR)) {
                @Nullable AuthenticatorModel model = getAuthenticatorModel(smsAuthenticatorACR, smsAuthenticatorACR);
                if (model != null) {
                    availableSecondFactors.add(model);
                }
            }
        });

        _emailAuthenticatorACR.ifPresent(emailAuthenticatorACR -> {
            if (!currentSecondFactorAcrs.containsValue(emailAuthenticatorACR)) {
                @Nullable AuthenticatorModel model = getAuthenticatorModel(emailAuthenticatorACR, emailAuthenticatorACR);
                if (model != null) {
                    availableSecondFactors.add(model);
                }
            }
        });

        response.putViewData("availableAuthenticators", availableSecondFactors, Response.ResponseModelScope.NOT_FAILURE);


        return Optional.empty();
    }

    @Override
    public Optional<ActionCompletionResult> post(ChooseAnotherFactorRequestModel request, Response response)
    {
        _sessionManager.put(Attribute.of(ANOTHER_SECOND_FACTOR_NAME, request.getSecondFactorName()));

        if (request.isDeleteSecondFactor()) {
            _sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, SECOND_FACTOR_CHOSEN_TO_DELETE));
        } else {
            _sessionManager.put(Attribute.of(ANOTHER_SECOND_FACTOR_ATTRIBUTE, request.getSecondFactor()));
            _sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, ANOTHER_NEW_SECOND_FACTOR_CHOSEN));
        }

        return Optional.of(ActionCompletionResult.complete());
    }

    @Override
    public ChooseAnotherFactorRequestModel preProcess(Request request, Response response)
    {
        @Nullable Attribute currentStepAttribute = _sessionManager.get(OPT_IN_MFA_STATE);

        if (currentStepAttribute == null) {
            _logger.info("No information about the step in session. This should not normally happen!");
            throw _exceptionFactory.badRequestException(ErrorCode.INVALID_SERVER_STATE);
        }

        OptInMFAState currentStep = OptInMFAState.valueOf(currentStepAttribute.getValueOfType(String.class));

        if (!NO_SECOND_FACTOR_CHOSEN.equals(currentStep)) {
            _logger.info("Registration of another second factor should never be called from other step than the first one in flow.");
            throw _exceptionFactory.badRequestException(ErrorCode.INVALID_SERVER_STATE);
        }

        ChooseAnotherFactorRequestModel requestModel = new ChooseAnotherFactorRequestModel(request);

        if (request.isPostRequest()) {
            if (requestModel.isDeleteSecondFactor()) {
                if (requestModel.getSecondFactorName() == null)
                {
                    throw new MissingSecondFactorParameterException();
                }
            } else {
                if (requestModel.getSecondFactor() == null)
                {
                    throw new MissingSecondFactorParameterException();
                }
            }
        }

        if (request.isGetRequest()) {
            response.setResponseModel(ResponseModel.templateResponseModel(Collections.emptyMap(),
                    "register"), Response.ResponseModelScope.NOT_FAILURE);
        }

        return requestModel;
    }

    @Nullable
    private AuthenticatorModel getAuthenticatorModel(String acr, String name)
    {
        try
        {
            NonEmptyList<AuthenticatorDescriptor> descriptor = _descriptorFactory.getAuthenticatorDescriptors(acr);
            return of(descriptor.getFirst(), name);
        }
        catch (AuthenticatorNotConfiguredException e)
        {
            _logger.info("Authenticator listed in configuration but not available in the system: {}", acr);
        }

        return null;
    }
}
