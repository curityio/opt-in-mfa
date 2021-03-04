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

import se.curity.identityserver.sdk.NonEmptyList
import se.curity.identityserver.sdk.attribute.AccountAttributes
import se.curity.identityserver.sdk.attribute.Attribute
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes
import se.curity.identityserver.sdk.attribute.ContextAttributes
import se.curity.identityserver.sdk.authentication.AuthenticatedSessions
import se.curity.identityserver.sdk.authenticationaction.AuthenticationActionResult
import se.curity.identityserver.sdk.authenticationaction.completions.RequiredActionCompletion
import se.curity.identityserver.sdk.errors.AuthenticatorNotConfiguredException
import se.curity.identityserver.sdk.service.AccountManager
import se.curity.identityserver.sdk.service.SessionManager
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptor
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptorFactory
import spock.lang.Shared
import spock.lang.Specification

import java.util.stream.Collectors

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.CHOSEN_SECOND_FACTOR_ATTRIBUTE
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.CHOSEN_SECOND_FACTOR_NAME
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.OPT_IN_MFA_STATE
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.FIRST_CHOICE_OF_SECOND_FACTOR
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.FIRST_SECOND_FACTOR_CHOSEN
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.FIRST_SECOND_FACTOR_REGISTERED
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.SCRATCH_CODES_CONFIRMED
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.SECOND_FACTOR_CHOSEN
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.SCRATCH_CODES

final class OptInMFAAuthenticationActionTest extends Specification {

    private def username = "john"
    private def authenticationAttributes = AuthenticationAttributes.of(username, ContextAttributes.empty())
    @Shared
    private def authenticator = Stub(AuthenticatorDescriptor)

    @Shared
    private def scratchCodeGenerator = new TestScratchCodeGenerator()

    def setupSpec()
    {
        authenticator.getAcr() >> "email"
    }

    def "should return pending result with proper flag set in session when user does not have any secondary factors"()
    {
        given:
        def sessionManager = getSessionManagerStubWithoutChosenSecondFactor()

        def user = getUserAttributes()
        def accountManager = getAccountManagerStubReturningUser(user)

        def configuration = new TestActionConfiguration(accountManager, null, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        when:
        def result = action.apply(authenticationAttributes, null, "transactionId", null)

        then:
        assert result instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        result.obligation instanceof RequiredActionCompletion.PromptUser
        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, FIRST_CHOICE_OF_SECOND_FACTOR))
    }

    def "should return pending result when user hasn't chosen a secondary factor yet"()
    {
        given:
        def sessionManager = getSessionManagerStubWithoutChosenSecondFactor()

        def user = getUserAttributes(["My email": "email"])
        def accountManager = getAccountManagerStubReturningUser(user)

        def configuration = new TestActionConfiguration(accountManager, null, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        def authenticatedSessions = authenticatedSessionsStubWithoutSessions()
        when:
        def result = action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then:
        assert result instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        result.obligation instanceof RequiredActionCompletion.PromptUser
    }

    def "should redirect to the authenticator when user has chosen a secondary factor"()
    {
        given:
        def sessionManager = getSessionManagerStubWithChosenSecondFactor("email")

        def user = getUserAttributes(["My email": "email"])
        def accountManager = getAccountManagerStubReturningUser(user)

        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("email")

        def authenticatedSessions = authenticatedSessionsStubWithoutSessions()

        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        when:
        def result = action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then:
        assert result instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = result.obligation
        assert obligation instanceof RequiredActionCompletion.AuthenticateUser

        def authenticatorDescriptor = obligation.authenticatorDescriptor
        authenticatorDescriptor.getAcr() == "email"
    }

    def "should throw an error when chosen secondary factor not configured or invalid"()
    {
        given:
        def sessionManager = getSessionManagerStubWithChosenSecondFactor("someValue")

        def user = getUserAttributes(["My email": "email"])
        def accountManager = getAccountManagerStubReturningUser(user)

        def descriptorFactory = authenticatorDescriptorFactoryStubThrowingError("someValue")

        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        def authenticatedSessions = authenticatedSessionsStubWithoutSessions()

        when:
        action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then:
        thrown IllegalStateException
    }

    def "should successfully complete action if secondary factor chosen and user already logged in using that factor"()
    {
        given:
        def sessionManager = getSessionManagerStubWithChosenSecondFactor("email")

        def user = getUserAttributes(["My email": "email"])
        def accountManager = getAccountManagerStubReturningUser(user)

        def authenticatedSessions = authenticatedSessionsStubWithSession("email")

        def configuration = new TestActionConfiguration(accountManager, null, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        when:
        def result = action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then:
        result instanceof AuthenticationActionResult.SuccessAuthenticationActionResult
    }

    def "should successfully complete action if there is sso session of any authenticator on the list"()
    {
        given:
        def sessionManager = getSessionManagerStubWithoutChosenSecondFactor()

        def user = getUserAttributes(["My email": "email"])
        def accountManager = getAccountManagerStubReturningUser(user)

        def authenticatedSessions = authenticatedSessionsStubWithSession("email")

        def configuration = new TestActionConfiguration(accountManager, null, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        when:
        def result = action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then:
        result instanceof AuthenticationActionResult.SuccessAuthenticationActionResult
    }

    def "should redirect to registration when first second factor chosen"()
    {
        given: "The user has chosen the second factor they want to configure."
        def sessionManager = getSessionManagerStubWithSecondFactorChosenForRegistration("email")

        and: "The user is registered and authenticator exists"
        def user = getUserAttributes()
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("email")
        def authenticatedSessions = authenticatedSessionsStubWithoutSessions()

        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        when: "The authentication action is called"
        def result = action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then: "The user should be redirected to registration action of the chosen authenticator"
        assert result instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = result.obligation
        assert obligation instanceof RequiredActionCompletion.RegisterUser

        def authenticatorDescriptor = obligation.authenticatorDescriptor
        authenticatorDescriptor.getAcr() == "email"

        and: "The state should be moved to next step"
        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_REGISTERED))
    }

    def "should process registered second factor"()
    {
        given: "The user has just registered a second factor"
        def sessionManager = getSessionManagerStubWithFirstSecondFactorRegistered("email")
        sessionManager.remove(CHOSEN_SECOND_FACTOR_NAME) >> Attribute.of(CHOSEN_SECOND_FACTOR_NAME, "My iPhone 11")

        and: "The user is registered and authenticator exists"
        def user = getUserAttributes()
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("email")
        def authenticatedSessions = authenticatedSessionsStubWithoutSessions()
        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        def secondFactors = ["My iPhone 11": "email"] as Map
        def scratchCodes = scratchCodeGenerator.generateScratchCodes()

        when: "The authentication action is called"
        def result = action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then: "The second factor and hashed scratch codes should be saved in the user profile."

        1 * accountManager.updateAccount({
            it.contains("secondFactors")
            it.get("secondFactors").getValue().forEach { k,v -> secondFactors.containsKey(k) && secondFactors[k] == v }
            it.contains("secondFactorCodes")
            it.get("secondFactorCodes").size() == 10
            it.get("secondFactorCodes").forEach { code -> !scratchCodes.contains(code) }
        })

        and: "The user should be redirected to the page showing the scratch codes."
        1 * sessionManager.put(Attribute.of(SCRATCH_CODES, scratchCodes))
        assert result instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = result.obligation
        assert obligation instanceof RequiredActionCompletion.PromptUser
    }

    def "should complete action in the final step"()
    {
        given: "The user confirmed the scratch codes"
        def sessionManager = Mock(SessionManager)
        sessionManager.get(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, SCRATCH_CODES_CONFIRMED)

        def accountManager = Stub(AccountManager)
        def descriptorFactory = Stub(AuthenticatorDescriptorFactory)
        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        def sessions = Stub(AuthenticatedSessions)

        when: "The authentication action is called"
        def response = action.apply(authenticationAttributes, sessions, "transactionId", null)

        then: "State is removed from the session"
        1 * sessionManager.remove(OPT_IN_MFA_STATE)

        and: "The action is completed"
        assert response instanceof AuthenticationActionResult.SuccessAuthenticationActionResult
    }

    private def getSessionManagerStubWithoutChosenSecondFactor()
    {
        getSessionManagerStub(false, false, null)
    }

    private def getSessionManagerStubWithChosenSecondFactor(String chosenFactor)
    {
        getSessionManagerStub(true, false, Attribute.of(CHOSEN_SECOND_FACTOR_ATTRIBUTE, chosenFactor))
    }

    private def getSessionManagerStubWithSecondFactorChosenForRegistration(String chosenFactor)
    {
        def sessionManager = Mock(SessionManager)
        sessionManager.get(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_CHOSEN)
        sessionManager.remove(CHOSEN_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(CHOSEN_SECOND_FACTOR_ATTRIBUTE, chosenFactor)

        sessionManager
    }

    private def getSessionManagerStubWithFirstSecondFactorRegistered(String chosenFactor)
    {
        getSessionManagerStub(false, true, Attribute.of(CHOSEN_SECOND_FACTOR_ATTRIBUTE, chosenFactor))
    }

    private def getSessionManagerStub(isSecondFactorChosen, isFirstSecondFactorRegistered, secondFactor)
    {
        def sessionManager = Mock(SessionManager)

        if (isSecondFactorChosen) {
            sessionManager.get(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, SECOND_FACTOR_CHOSEN)
            sessionManager.remove(CHOSEN_SECOND_FACTOR_ATTRIBUTE) >> secondFactor
        }
        else if (isFirstSecondFactorRegistered)
        {
            sessionManager.get(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_REGISTERED)
            sessionManager.remove(CHOSEN_SECOND_FACTOR_ATTRIBUTE) >> secondFactor
        }
        else
        {
            sessionManager.get(OPT_IN_MFA_STATE) >> null
        }

        sessionManager
    }

    private def authenticatorDescriptorFactoryStubThrowingError(acr)
    {
        def descriptor = Stub(AuthenticatorDescriptorFactory)
        descriptor.getAuthenticatorDescriptors(acr) >> { throw new AuthenticatorNotConfiguredException("Not configured") }
        descriptor
    }

    private def authenticatorDescriptorFactoryStubReturningDescriptor(acr)
    {
        def descriptor = Stub(AuthenticatorDescriptorFactory)
        descriptor.getAuthenticatorDescriptors(acr) >> NonEmptyList.of(authenticator)
        descriptor
    }

    private def getUserAttributes(secondFactors)
    {
        def user = AccountAttributes.fromMap(["id": "1234", "subject": username])
        if (secondFactors)
        {
            user = AccountAttributes.fromMap(["id": "1234", "subject": username, "secondFactors": secondFactors])
        }
        user
    }

    private def getAccountManagerStubReturningUser(user)
    {
        def accountManager = Mock(AccountManager)
        accountManager.getByUserName(username) >> user
        accountManager
    }

    private def authenticatedSessionsStubWithoutSessions()
    {
        def authenticatedSessions = Stub(AuthenticatedSessions)
        authenticatedSessions.contains(_) >> false
        authenticatedSessions
    }

    private def authenticatedSessionsStubWithSession(acr)
    {
        def authenticatedSessions = Stub(AuthenticatedSessions)
        authenticatedSessions.contains(acr) >> true
        authenticatedSessions
    }

    private static class TestScratchCodeGenerator extends ScratchCodeGenerator
    {
        TestScratchCodeGenerator() {
            super(null)
        }

        @Override
        List<String> generateScratchCodes() {
            return (1..10).stream().map {it.toString()}.collect(Collectors.toList())
        }
    }
}
