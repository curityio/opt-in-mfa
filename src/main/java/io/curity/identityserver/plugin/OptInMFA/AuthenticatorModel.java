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

import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptor;

public final class AuthenticatorModel
{
    private final String _id;
    private final String _description;
    private final String _type;

    public AuthenticatorModel(String id, @Nullable String description, String type)
    {
        _id = id;
        if (description != null)
        {
            _description = description;
        }
        else
        {
            _description = id;
        }

        _type = type;
    }

    public String getId()
    {
        return _id;
    }

    public String getDescription()
    {
        return _description;
    }

    public String getType()
    {
        return _type;
    }

    public static AuthenticatorModel toAuthenticatorModel(AuthenticatorDescriptor descriptor)
    {
        //TODO - there should be a way to get the type from somewhere
        return new AuthenticatorModel(descriptor.getId(), descriptor.getDescription(), "html-form");
    }
}
