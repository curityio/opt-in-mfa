package io.curity.identityserver.plugin.OptInMFA.handler;

import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.service.SessionManager;

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.OPT_IN_MFA_STATE;
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.FIRST_CHOICE_OF_SECOND_FACTOR;

abstract public class OptInMFAHandler
{
    protected final SessionManager _sessionManager;

    public OptInMFAHandler(SessionManager sessionManager)
    {
        _sessionManager = sessionManager;
    }

    public boolean isInFirstChoiceState() {
        Attribute currentState = _sessionManager.get(OPT_IN_MFA_STATE);

        if (currentState == null) {
            return false;
        }

        return currentState.getValueOfType(String.class).equals(FIRST_CHOICE_OF_SECOND_FACTOR.toString());
    }
}
