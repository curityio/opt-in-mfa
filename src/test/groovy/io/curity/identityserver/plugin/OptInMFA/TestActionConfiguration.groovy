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
package io.curity.identityserver.plugin.OptInMFA

import se.curity.identityserver.sdk.service.AccountManager
import se.curity.identityserver.sdk.service.SessionManager
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptorFactory

class TestActionConfiguration implements OptInMFAAuthenticationActionConfig
{
    private final AccountManager _accountManager;
    private final AuthenticatorDescriptorFactory _authenticatorDescriptorFactory;
    private final SessionManager _sessionManager;

    TestActionConfiguration(AccountManager accountManager, AuthenticatorDescriptorFactory authenticatorDescriptorFactory, SessionManager sessionManager) {
        _accountManager = accountManager
        _authenticatorDescriptorFactory = authenticatorDescriptorFactory
        _sessionManager = sessionManager
    }

    @Override
    AccountManager getAccountManager() {
        _accountManager
    }

    @Override
    AuthenticatorDescriptorFactory getAuthenticatorDescriptorFactory() {
        _authenticatorDescriptorFactory
    }

    @Override
    SessionManager getSessionManager() {
        _sessionManager
    }

    @Override
    int getRememberMyChoiceDaysLimit() {
        30
    }

    @Override
    String id() {
        ""
    }

    @Override
    List<String> availableAuthenticators() {
        List authenticators = new ArrayList<String>(2)
        authenticators.add("acr1")
        authenticators.add("acr2")

        authenticators
    }
}
