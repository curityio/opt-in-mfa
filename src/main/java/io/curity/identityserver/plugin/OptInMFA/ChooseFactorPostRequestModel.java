package io.curity.identityserver.plugin.OptInMFA;

import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.web.Request;

public class ChooseFactorPostRequestModel
{
    private final String _secondFactor;
    @Nullable
    private final String _rememberChoice;
    @Nullable
    private final String _secondFactorName;

    public ChooseFactorPostRequestModel(Request request)
    {
        _secondFactor = request.getFormParameterValueOrError("secondFactor");
        if (_secondFactor == null)
        {
            throw new MissingSecondFactorParameterException();
        }

        _rememberChoice = request.getFormParameterValueOrError("rememberChoice");
        _secondFactorName = request.getFormParameterValueOrError("secondFactorName");
    }

    public String getSecondFactor()
    {
        return _secondFactor;
    }

    public String getRememberChoice()
    {
        return _rememberChoice;
    }

    public String getSecondFactorName()
    {
        return _secondFactorName;
    }
}
