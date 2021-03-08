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
import se.curity.identityserver.sdk.service.ExceptionFactory
import se.curity.identityserver.sdk.service.SessionManager
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptorFactory

class TestActionConfiguration implements OptInMFAAuthenticationActionConfig
{
    private AccountManager _accountManager
    private AuthenticatorDescriptorFactory _authenticatorDescriptorFactory
    private final SessionManager _sessionManager
    private ExceptionFactory _exceptionFactory

    TestActionConfiguration(AccountManager accountManager, AuthenticatorDescriptorFactory authenticatorDescriptorFactory, SessionManager sessionManager) {
        _accountManager = accountManager
        _authenticatorDescriptorFactory = authenticatorDescriptorFactory
        _sessionManager = sessionManager
    }

    TestActionConfiguration(AccountManager accountManager, SessionManager sessionManager, ExceptionFactory exceptionFactory) {
        _accountManager = accountManager
        _exceptionFactory = exceptionFactory
        _sessionManager = sessionManager
    }

    TestActionConfiguration() {}

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
    List<String> getAvailableAuthenticators() {
        List authenticators = new ArrayList<String>(2)
        authenticators.add("acr1")
        authenticators.add("acr2")

        authenticators
    }

    @Override
    ExceptionFactory getExceptionFactory() {
        return _exceptionFactory
    }
}
