package io.curity.identityserver.plugin.OptInMFA;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.NonEmptyList;
import se.curity.identityserver.sdk.authenticationaction.completions.ActionCompletionRequestHandler;
import se.curity.identityserver.sdk.authenticationaction.completions.ActionCompletionResult;
import se.curity.identityserver.sdk.errors.AuthenticatorNotConfiguredException;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptor;
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptorFactory;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.lang.invoke.MethodHandles;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.AVAILABLE_SECOND_FACTORS_ATTRIBUTE;
import static io.curity.identityserver.plugin.OptInMFA.AuthenticatorModel.toAuthenticatorModel;
import static java.util.Collections.EMPTY_MAP;
import static se.curity.identityserver.sdk.web.ResponseModel.templateResponseModel;

public final class OptInMFAuthenticationActionHandler implements ActionCompletionRequestHandler<Request>
{
    private static final Logger _logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private final AuthenticatorDescriptorFactory _authenticatorDescriptorFactory;
    private final SessionManager _sessionManager;

    public OptInMFAuthenticationActionHandler(AuthenticatorDescriptorFactory factory, SessionManager sessionManager)
    {
        _authenticatorDescriptorFactory = factory;
        _sessionManager = sessionManager;
    }

    @Override
    public Optional<ActionCompletionResult> get(Request request, Response response)
    {
        Map<String, String> secondFactors = (Map<String, String>) _sessionManager.get(AVAILABLE_SECOND_FACTORS_ATTRIBUTE).getValue();
        _sessionManager.remove(AVAILABLE_SECOND_FACTORS_ATTRIBUTE);

        Map<String, AuthenticatorModel> authenticators = new HashMap<>(secondFactors.size());

        secondFactors.forEach((k, v) -> {
            try
            {
                NonEmptyList<AuthenticatorDescriptor> descriptor = _authenticatorDescriptorFactory.getAuthenticatorDescriptors(v);
                authenticators.put(k, toAuthenticatorModel(descriptor.getFirst()));

            }
            catch (AuthenticatorNotConfiguredException e)
            {
                e.printStackTrace();
            }
        });

        response.putViewData("authenticators", authenticators, Response.ResponseModelScope.NOT_FAILURE);

        return Optional.empty();
    }

    @Override
    public Optional<ActionCompletionResult> post(Request request, Response response)
    {
        return Optional.empty();
    }

    @Override
    public Request preProcess(Request request, Response response)
    {
        response.setResponseModel(templateResponseModel(EMPTY_MAP,
                "index"), Response.ResponseModelScope.NOT_FAILURE);
        return request;
    }
}
