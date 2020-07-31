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
package io.curity.identityserver.plugin.OptInMFA.descriptor;

import io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction;
import io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationActionConfig;
import io.curity.identityserver.plugin.OptInMFA.OptInMFAChooseFactorHandler;
import io.curity.identityserver.plugin.OptInMFA.OptInMFAuthenticationActionHandler;
import se.curity.identityserver.sdk.authenticationaction.AuthenticationAction;
import se.curity.identityserver.sdk.authenticationaction.completions.ActionCompletionRequestHandler;
import se.curity.identityserver.sdk.plugin.descriptor.AuthenticationActionPluginDescriptor;
import se.curity.identityserver.sdk.web.RequestHandlerSet;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public final class OptInMFAAuthenticationActionDescriptor implements AuthenticationActionPluginDescriptor<OptInMFAAuthenticationActionConfig>
{
    private static final Map<String, Class<? extends ActionCompletionRequestHandler<?>>> _handlerTypes;

    static
    {
        Map<String, Class<? extends ActionCompletionRequestHandler<?>>> handlerTypes = new HashMap<>(2);
        handlerTypes.put("index", OptInMFAuthenticationActionHandler.class);
        handlerTypes.put("chooseFactor", OptInMFAChooseFactorHandler.class);
        _handlerTypes = Collections.unmodifiableMap(handlerTypes);
    }

    @Override
    public Class<? extends AuthenticationAction> getAuthenticationAction()
    {
        return OptInMFAAuthenticationAction.class;
    }

    @Override
    public String getPluginImplementationType()
    {
        return "opt-in-mfa";
    }

    @Override
    public Class<? extends OptInMFAAuthenticationActionConfig> getConfigurationType()
    {
        return OptInMFAAuthenticationActionConfig.class;
    }

    @Override
    public Map<String, Class<? extends ActionCompletionRequestHandler<?>>> getAuthenticationActionRequestHandlerTypes()
    {
        return _handlerTypes;
    }

    @Override
    public RequestHandlerSet allowedHandlersForCrossSiteNonSafeRequests()
    {
        return RequestHandlerSet.none();
    }
}
