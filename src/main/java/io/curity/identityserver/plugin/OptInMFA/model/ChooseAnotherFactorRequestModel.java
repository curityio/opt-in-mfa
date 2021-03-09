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
package io.curity.identityserver.plugin.OptInMFA.model;

import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.web.Request;

public class ChooseAnotherFactorRequestModel
{
    private final String _secondFactor;
    @Nullable
    private final String _secondFactorName;
    @Nullable
    private final boolean _deleteSecondFactor;

    public ChooseAnotherFactorRequestModel(Request request)
    {
        _secondFactor = request.getFormParameterValueOrError("secondFactor");
        _secondFactorName = request.getFormParameterValueOrError("secondFactorName");
        @Nullable String deleteSecondFactorParameter = request.getFormParameterValueOrError("deleteFactor");
        _deleteSecondFactor = deleteSecondFactorParameter != null && deleteSecondFactorParameter.equals("true");
    }

    public String getSecondFactor()
    {
        return _secondFactor;
    }

    public String getSecondFactorName()
    {
        return _secondFactorName;
    }

    public boolean isDeleteSecondFactor()
    {
        return _deleteSecondFactor;
    }
}
