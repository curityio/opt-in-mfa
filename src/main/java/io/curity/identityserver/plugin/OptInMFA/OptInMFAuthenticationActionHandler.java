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
import se.curity.identityserver.sdk.NonEmptyList;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.attribute.AttributeValue;
import se.curity.identityserver.sdk.attribute.MapAttributeValue;
import se.curity.identityserver.sdk.authenticationaction.completions.ActionCompletionRequestHandler;
import se.curity.identityserver.sdk.authenticationaction.completions.ActionCompletionResult;
import se.curity.identityserver.sdk.errors.AuthenticatorNotConfiguredException;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptor;
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptorFactory;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;
import se.curity.identityserver.sdk.web.cookie.Cookie;

import java.lang.invoke.MethodHandles;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.AVAILABLE_SECOND_FACTORS_ATTRIBUTE;
import static io.curity.identityserver.plugin.OptInMFA.AuthenticatorModel.of;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.CHOSEN_SECOND_FACTOR_ATTRIBUTE;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.REMEMBER_CHOICE_COOKIE_NAME;
import static java.util.Collections.EMPTY_MAP;
import static se.curity.identityserver.sdk.web.ResponseModel.templateResponseModel;

public final class OptInMFAuthenticationActionHandler implements ActionCompletionRequestHandler<Request>
{
    private static final Logger _logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private final AuthenticatorDescriptorFactory _authenticatorDescriptorFactory;
    private final SessionManager _sessionManager;
    private final OptInMFAAuthenticationActionConfig _configuration;
    private final ExceptionFactory _exceptionFactory;

    public OptInMFAuthenticationActionHandler(
            AuthenticatorDescriptorFactory factory,
            SessionManager sessionManager,
            OptInMFAAuthenticationActionConfig configuration,
            ExceptionFactory exceptionFactory)
    {
        _authenticatorDescriptorFactory = factory;
        _sessionManager = sessionManager;
        _configuration = configuration;
        _exceptionFactory = exceptionFactory;
    }

    @Override
    public Optional<ActionCompletionResult> get(Request request, Response response)
    {
        @Nullable Attribute secondFactorsAttribute = _sessionManager.remove(AVAILABLE_SECOND_FACTORS_ATTRIBUTE);

        if (secondFactorsAttribute == null)
        {
            throw new SecondFactorsInvalidException();
        }

        AttributeValue value = secondFactorsAttribute.getAttributeValue();

        if (!(value instanceof MapAttributeValue))
        {
            throw new SecondFactorsInvalidException();
        }

        Map<String, Object> secondFactors = ((MapAttributeValue) value).getValue();

        Map<String, AuthenticatorModel> authenticators = new HashMap<>(secondFactors.size());

        secondFactors.forEach((name, acr) -> {
            try
            {
                NonEmptyList<AuthenticatorDescriptor> descriptor = _authenticatorDescriptorFactory.getAuthenticatorDescriptors((String) acr);
                authenticators.put((String) acr, of(descriptor.getFirst(), name));
            }
            catch (AuthenticatorNotConfiguredException e)
            {
                _logger.info("Authenticator listed on user's profile but not available in system: {}", acr);
            }
        });

        Cookie rememberChoiceCookie = request.getCookies().getFirst(REMEMBER_CHOICE_COOKIE_NAME);

        if (rememberChoiceCookie != null && authenticators.containsKey(rememberChoiceCookie.getValue()))
        {
            _sessionManager.put(Attribute.of(CHOSEN_SECOND_FACTOR_ATTRIBUTE, rememberChoiceCookie.getValue()));
            _sessionManager.put(Attribute.ofFlag(IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE));
            return Optional.of(ActionCompletionResult.complete());
        }

        response.putViewData("authenticators", authenticators, Response.ResponseModelScope.NOT_FAILURE);
        response.putViewData("rememberMyChoiceDays", _configuration.getRememberMyChoiceDaysLimit(), Response.ResponseModelScope.NOT_FAILURE);

        return Optional.empty();
    }

    @Override
    public Optional<ActionCompletionResult> post(Request request, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    @Override
    public Request preProcess(Request request, Response response)
    {
        response.setResponseModel(templateResponseModel(EMPTY_MAP,
                "index"), Response.ResponseModelScope.NOT_FAILURE);
        return request;
    }
}
