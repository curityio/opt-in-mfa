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
package io.curity.identityserver.plugin.OptInMFA.handler;

import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.authenticationaction.completions.ActionCompletionRequestHandler;
import se.curity.identityserver.sdk.authenticationaction.completions.ActionCompletionResult;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;
import java.util.Optional;

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.OPT_IN_MFA_STATE;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.SCRATCH_CODES_CONFIRMED;

public final class OptInMFAConfirmCodesHandler implements ActionCompletionRequestHandler<Request>
{
    private final SessionManager _sessionManager;
    private final ExceptionFactory _exceptionFactory;

    public OptInMFAConfirmCodesHandler(SessionManager sessionManager, ExceptionFactory exceptionFactory)
    {
        _sessionManager = sessionManager;
        _exceptionFactory = exceptionFactory;
    }

    @Override
    public Optional<ActionCompletionResult> get(Request request, Response response)
    {
        _sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, SCRATCH_CODES_CONFIRMED));
        return Optional.of(ActionCompletionResult.complete());
    }

    @Override
    public Optional<ActionCompletionResult> post(Request request, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();

    }

    @Override
    public Request preProcess(Request request, Response response)
    {
        if (!request.isGetRequest())
        {
            throw _exceptionFactory.methodNotAllowed();
        }

        return request;
    }
}
