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

import io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationActionConfig;
import io.curity.identityserver.plugin.OptInMFA.OptInMFAState;
import io.curity.identityserver.plugin.OptInMFA.exception.MissingSecondFactorParameterException;
import io.curity.identityserver.plugin.OptInMFA.model.AuthenticatorModel;
import io.curity.identityserver.plugin.OptInMFA.model.EmergencyFactorRegistrationRequestModel;
import org.apache.commons.codec.digest.DigestUtils;
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
import java.util.Optional;

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.CHOSEN_SECOND_FACTOR_ATTRIBUTE;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.CHOSEN_SECOND_FACTOR_NAME;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.EMERGENCY_REGISTRATION_OF_SECOND_FACTOR;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.OPT_IN_MFA_STATE;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.SCRATCH_CODE;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.SECOND_FACTOR_CODES;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.SUBJECT;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.FIRST_SECOND_FACTOR_CHOSEN;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.NO_SECOND_FACTOR_CHOSEN;
import static io.curity.identityserver.plugin.OptInMFA.model.AuthenticatorModel.of;

public final class OptInMFAEmergencyRegisterFactorHandler implements ActionCompletionRequestHandler<EmergencyFactorRegistrationRequestModel>
{
    private final SessionManager _sessionManager;
    private final ExceptionFactory _exceptionFactory;
    private final AuthenticatorDescriptorFactory _descriptorFactory;
    private final List<String> _availableSecondFactors;
    private final AccountManager _accountManager;

    public static final Logger _logger = LoggerFactory.getLogger(OptInMFAEmergencyRegisterFactorHandler.class);

    public OptInMFAEmergencyRegisterFactorHandler(AuthenticatorDescriptorFactory descriptorFactory, OptInMFAAuthenticationActionConfig configuration)
    {
        _descriptorFactory = descriptorFactory;
        _sessionManager = configuration.getSessionManager();
        _exceptionFactory = configuration.getExceptionFactory();
        _availableSecondFactors = configuration.getAvailableAuthenticators();
        _accountManager = configuration.getAccountManager();
    }

    @Override
    public Optional<ActionCompletionResult> get(EmergencyFactorRegistrationRequestModel request, Response response)
    {
        List<AuthenticatorModel> availableSecondFactors = new ArrayList<>(_availableSecondFactors.size());

        _availableSecondFactors.forEach(acr -> {
            try
            {
                NonEmptyList<AuthenticatorDescriptor> descriptor = _descriptorFactory.getAuthenticatorDescriptors(acr);
                availableSecondFactors.add(of(descriptor.getFirst(), acr));
            }
            catch (AuthenticatorNotConfiguredException e)
            {
                _logger.info("Authenticator listed in configuration but not available in the system: {}", acr);
            }
        });

        response.putViewData("availableAuthenticators", availableSecondFactors, Response.ResponseModelScope.NOT_FAILURE);

        return Optional.empty();
    }

    @Override
    public Optional<ActionCompletionResult> post(EmergencyFactorRegistrationRequestModel request, Response response)
    {
        String subject = _sessionManager.get(SUBJECT).getValueOfType(String.class);
        AccountAttributes user = _accountManager.getByUserName(subject);
        Attribute userCodesAttribute = user.get(SECOND_FACTOR_CODES);

        if (userCodesAttribute == null) {
            throw _exceptionFactory.badRequestException(ErrorCode.ACCESS_DENIED);
        }

        List<String> userCodes = userCodesAttribute.getValueOfType(List.class);

        String hashedCode = DigestUtils.sha256Hex(request.getScratchCode());

        if (!userCodes.contains(hashedCode)) {
            response.putViewData("wrongCode", true, Response.ResponseModelScope.NOT_FAILURE);
            response.setResponseModel(ResponseModel.templateResponseModel(Collections.emptyMap(),
                    "emergencyRegister"), Response.ResponseModelScope.NOT_FAILURE);
            return get(request, response);
        }

        _sessionManager.put(Attribute.of(CHOSEN_SECOND_FACTOR_ATTRIBUTE, request.getSecondFactor()));
        _sessionManager.put(Attribute.of(CHOSEN_SECOND_FACTOR_NAME, request.getSecondFactorName()));
        _sessionManager.put(Attribute.of(SCRATCH_CODE, request.getScratchCode()));
        _sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_CHOSEN));
        _sessionManager.put(Attribute.ofFlag(EMERGENCY_REGISTRATION_OF_SECOND_FACTOR));

        return Optional.of(ActionCompletionResult.complete());
    }

    @Override
    public EmergencyFactorRegistrationRequestModel preProcess(Request request, Response response)
    {
        @Nullable Attribute currentStepAttribute = _sessionManager.get(OPT_IN_MFA_STATE);

        if (currentStepAttribute == null) {
            _logger.info("No information about the step in session. This should not normally happen!");
            throw _exceptionFactory.badRequestException(ErrorCode.INVALID_SERVER_STATE);
        }

        OptInMFAState currentStep = OptInMFAState.valueOf(currentStepAttribute.getValueOfType(String.class));

        if (!NO_SECOND_FACTOR_CHOSEN.equals(currentStep)) {
            _logger.info("Emergency registration of another second factor should never be called from other step than the first one in flow.");
            throw _exceptionFactory.badRequestException(ErrorCode.INVALID_SERVER_STATE);
        }

        EmergencyFactorRegistrationRequestModel requestModel = new EmergencyFactorRegistrationRequestModel(request);

        if (request.isPostRequest()) {
            if (requestModel.getSecondFactor() == null || requestModel.getScratchCode() == null)
            {
                throw new MissingSecondFactorParameterException();
            }
        }

        if (request.isGetRequest()) {
            response.setResponseModel(ResponseModel.templateResponseModel(Collections.emptyMap(),
                    "emergencyRegister"), Response.ResponseModelScope.NOT_FAILURE);
        }

        return requestModel;
    }
}
