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

import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.authenticationaction.completions.ActionCompletionRequestHandler;
import se.curity.identityserver.sdk.authenticationaction.completions.ActionCompletionResult;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;
import se.curity.identityserver.sdk.web.cookie.StandardResponseCookie;

import java.time.Duration;
import java.util.Optional;

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.CHOSEN_SECOND_FACTOR_ATTRIBUTE;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.REMEMBER_CHOICE_COOKIE_NAME;

public final class OptInMFAChooseFactorHandler implements ActionCompletionRequestHandler<ChooseFactorPostRequestModel>
{
    private final SessionManager _sessionManager;
    private final ExceptionFactory _exceptionFactory;
    private final int _rememberChoiceDays;

    public OptInMFAChooseFactorHandler(SessionManager sessionManager, ExceptionFactory exceptionFactory, OptInMFAAuthenticationActionConfig configuration)
    {
        _sessionManager = sessionManager;
        _exceptionFactory = exceptionFactory;
        _rememberChoiceDays = configuration.getRememberMyChoiceDaysLimit();
    }

    @Override
    public Optional<ActionCompletionResult> get(ChooseFactorPostRequestModel request, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    @Override
    public Optional<ActionCompletionResult> post(ChooseFactorPostRequestModel request, Response response)
    {
        _sessionManager.put(Attribute.of(CHOSEN_SECOND_FACTOR_ATTRIBUTE, request.getSecondFactor()));
        _sessionManager.put(Attribute.ofFlag(IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE));

        String rememberChoice = request.getRememberChoice();

        if (rememberChoice != null)
        {
            StandardResponseCookie cookie = new StandardResponseCookie(REMEMBER_CHOICE_COOKIE_NAME, request.getSecondFactor());
            cookie.setMaxAge(Duration.ofDays(_rememberChoiceDays));
            response.cookies().add(cookie);
        }

        return Optional.of(ActionCompletionResult.complete());
    }

    @Override
    public ChooseFactorPostRequestModel preProcess(Request request, Response response)
    {
        if (!request.isPostRequest())
        {
            throw _exceptionFactory.methodNotAllowed();
        }

        return new ChooseFactorPostRequestModel(request);
    }
}
