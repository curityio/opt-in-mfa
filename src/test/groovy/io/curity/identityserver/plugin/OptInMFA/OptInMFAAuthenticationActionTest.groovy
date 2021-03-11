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

import org.apache.commons.codec.digest.DigestUtils
import se.curity.identityserver.sdk.NonEmptyList
import se.curity.identityserver.sdk.attribute.AccountAttributes
import se.curity.identityserver.sdk.attribute.Attribute
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes
import se.curity.identityserver.sdk.attribute.ContextAttributes
import se.curity.identityserver.sdk.attribute.ListAttributeValue
import se.curity.identityserver.sdk.attribute.MapAttributeValue
import se.curity.identityserver.sdk.attribute.scim.v2.multivalued.PhoneNumber
import se.curity.identityserver.sdk.authentication.AuthenticatedSessions
import se.curity.identityserver.sdk.authenticationaction.AuthenticationActionResult
import se.curity.identityserver.sdk.authenticationaction.completions.RequiredActionCompletion
import se.curity.identityserver.sdk.errors.AuthenticatorNotConfiguredException
import se.curity.identityserver.sdk.errors.ErrorCode
import se.curity.identityserver.sdk.service.AccountManager
import se.curity.identityserver.sdk.service.ExceptionFactory
import se.curity.identityserver.sdk.service.SessionManager
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptor
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptorFactory
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import java.util.stream.Collectors

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.ANOTHER_SECOND_FACTOR_ATTRIBUTE
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.ANOTHER_SECOND_FACTOR_NAME
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.AUTHENTICATION_TRANSACTION
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.CHOSEN_SECOND_FACTOR_ATTRIBUTE
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.CHOSEN_SECOND_FACTOR_NAME
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.DELETION_OF_SECOND_FACTOR
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.EMERGENCY_REGISTRATION_OF_SECOND_FACTOR
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.FORCE_SHOW_LIST_OF_SECOND_FACTORS
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.OPT_IN_MFA_STATE
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.REGISTRATION_OF_ANOTHER_SECOND_FACTOR
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.SCRATCH_CODE
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.SECOND_FACTOR_CODES
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.ANOTHER_NEW_SECOND_FACTOR_CHOSEN
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.ANOTHER_NEW_SECOND_FACTOR_REGISTERED
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.FIRST_CHOICE_OF_SECOND_FACTOR
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.FIRST_SECOND_FACTOR_CHOSEN
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.FIRST_SECOND_FACTOR_REGISTERED
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.NO_SECOND_FACTOR_CHOSEN
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.SCRATCH_CODES_CONFIRMED
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.SECOND_FACTOR_CHOSEN
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.SCRATCH_CODES
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.SECOND_FACTOR_CHOSEN_TO_DELETE

final class OptInMFAAuthenticationActionTest extends Specification {

    private def username = "john"
    private def authenticationAttributes = AuthenticationAttributes.of(username, ContextAttributes.empty())

    @Shared
    private def scratchCodeGenerator = new TestScratchCodeGenerator()

    def "should return pending result with proper flag set in session when user does not have any secondary factors (start the registration flow)"()
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

    @Unroll
    def "should process registered first second factor without registration for the special {} authenticator"(String acr)
    {
        given: "The user has just chosen a special first second factor."
        def sessionManager = Mock(SessionManager)
        sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_CHOSEN)
        sessionManager.get(CHOSEN_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(CHOSEN_SECOND_FACTOR_ATTRIBUTE, acr)
        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "transactionId")

        and: "The user is registered and authenticator exists."
        def user = getUserAttributes()
            .withPhoneNumbers(PhoneNumber.of("123456789", true))
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor(acr)
        def authenticatedSessions = authenticatedSessionsStubWithoutSessions()
        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        def secondFactors = ["my second factor": acr] as Map
        def scratchCodes = scratchCodeGenerator.generateScratchCodes()

        when: "The authentication action is called."
        def result = action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then: "The second factor and hashed scratch codes should be saved in the user profile."

        1 * accountManager.updateAccount({
            it.contains("secondFactors")
            it.get("secondFactors").getValue().forEach { k,v -> secondFactors.containsKey(k) && secondFactors[k] == v }
            it.contains("secondFactorCodes")
            it.get("secondFactorCodes").size() == 10
            // Check that the codes in profile are different from raw codes from the generator - so they must have been hashed.
            it.get("secondFactorCodes").forEach { code -> !scratchCodes.contains(code) }
        })

        and: "The user should be redirected to the page showing the scratch codes."
        1 * sessionManager.put(Attribute.of(SCRATCH_CODES, scratchCodes))
        1 * sessionManager.remove(CHOSEN_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(CHOSEN_SECOND_FACTOR_ATTRIBUTE, acr)
        1 * sessionManager.remove(CHOSEN_SECOND_FACTOR_NAME) >> Attribute.of(CHOSEN_SECOND_FACTOR_NAME, "my second factor")
        assert result instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = result.obligation
        assert obligation instanceof RequiredActionCompletion.PromptUser

        where:
        acr << ["acr-email", "acr-sms"]
    }

    def "should redirect to registration for special sms authenticator if user doesn't have a phone number"()
    {
        given: "The user has chosen the special sms second factor as their first factor."
        def sessionManager = getSessionManagerStubWithSecondFactorChosenForRegistration("acr-sms")

        and: "The user is registered and authenticator exists."
        def user = getUserAttributes()
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("acr-sms")
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
        authenticatorDescriptor.getAcr() == "acr-sms"

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
            // Check that the codes in profile are different from raw codes from the generator - so they must have been hashed.
            it.get("secondFactorCodes").forEach { code -> !scratchCodes.contains(code) }
        })

        and: "The user should be redirected to the page showing the scratch codes."
        1 * sessionManager.put(Attribute.of(SCRATCH_CODES, scratchCodes))
        assert result instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = result.obligation
        assert obligation instanceof RequiredActionCompletion.PromptUser
    }

    def "should use ACR as name for the second factor if user did not set name"()
    {
        given: "The user has just registered a second factor without specifying the name."
        def sessionManager = getSessionManagerStubWithFirstSecondFactorRegistered("email")
        sessionManager.remove(CHOSEN_SECOND_FACTOR_NAME) >> null

        and: "The user is registered and authenticator exists."
        def user = getUserAttributes()
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("email")
        def authenticatedSessions = authenticatedSessionsStubWithoutSessions()
        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        def secondFactors = ["email": "email"] as Map

        when: "The authentication action is called"
        action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then: "The second factor should be saved in the user profile using acr as the name."

        1 * accountManager.updateAccount({
            it.contains("secondFactors")
            it.get("secondFactors").getValue().forEach { k, v -> secondFactors.containsKey(k) && secondFactors[k] == v }
        })
    }

    def "should restart process if transactionId changed"()
    {
        given: "There is a state in session and some transaction ID."
        def sessionManager = Mock(SessionManager)
        sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_REGISTERED)
        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "someTransactionId")

        and: "The action is configured with proper objects."
        def user = getUserAttributes([])
        def accountManager = getAccountManagerStubReturningUser(user)
        def configuration = new TestActionConfiguration(accountManager, null, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        def authenticatedSessions = Stub(AuthenticatedSessions)

        when: "The action is called with a different transaction ID."
        def result = action.apply(authenticationAttributes, authenticatedSessions, "otherTransactionId", null)

        then: "All session entries connected to the opt-in-mfa flow are cleared."
        1 * sessionManager.remove(CHOSEN_SECOND_FACTOR_ATTRIBUTE)
        1 * sessionManager.remove(CHOSEN_SECOND_FACTOR_NAME)
        1 * sessionManager.remove(SCRATCH_CODES)
        1 * sessionManager.remove(ANOTHER_SECOND_FACTOR_ATTRIBUTE)
        1 * sessionManager.remove(ANOTHER_SECOND_FACTOR_NAME)
        1 * sessionManager.remove(REGISTRATION_OF_ANOTHER_SECOND_FACTOR)
        1 * sessionManager.remove(EMERGENCY_REGISTRATION_OF_SECOND_FACTOR)
        1 * sessionManager.remove(SCRATCH_CODE)
        1 * sessionManager.remove(DELETION_OF_SECOND_FACTOR)
        1 * sessionManager.remove(FORCE_SHOW_LIST_OF_SECOND_FACTORS)

        and: "The new transaction ID is saved in session and step reset."
        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, NO_SECOND_FACTOR_CHOSEN))
        1 * sessionManager.put(Attribute.of(AUTHENTICATION_TRANSACTION, "otherTransactionId"))

        and: "The user is displayed the first screen of the flow."
        assert result instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = result.obligation
        assert obligation instanceof RequiredActionCompletion.PromptUser
    }

    def "should redirect user back to second factor choice after successful completion of registering first second factor"()
    {
        given: "The user confirmed the scratch codes after registration of first second factor"
        def sessionManager = Mock(SessionManager)
        sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, SCRATCH_CODES_CONFIRMED)
        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "transactionId")

        def user = getUserAttributes(["My email": "email"])
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = Stub(AuthenticatorDescriptorFactory)
        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        def sessions = Stub(AuthenticatedSessions)

        when: "The authentication action is called"
        def response = action.apply(authenticationAttributes, sessions, "transactionId", null)

        then: "The action returns to the first state and displays list of second factors"
        assert response instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, NO_SECOND_FACTOR_CHOSEN))
    }

    def "should require authentication with second factor when another second factor is to be registered"()
    {
        given: "The user has chosen another second factor."
        def sessionManager = Mock(SessionManager)
        sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, ANOTHER_NEW_SECOND_FACTOR_CHOSEN)
        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "transactionId")

        and: "The user has a registered second factor."
        def user = getUserAttributes(["My iPhone 11": "sms"])
        def accountManager = getAccountManagerStubReturningUser(user)
        def factory = Stub(AuthenticatorDescriptorFactory)
        def configuration = new TestActionConfiguration(accountManager, factory, sessionManager)

        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        and: "The user is not authenticated with any other second factor"
        def sessions = authenticatedSessionsStubWithoutSessions()

        when: "When the action is applied."
        def response = action.apply(authenticationAttributes, sessions, "transactionId", null)

        then: "The user is redirected to start of process (authenticate with a second factor)."
        assert response instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = response.obligation
        assert obligation instanceof RequiredActionCompletion.PromptUser
        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, NO_SECOND_FACTOR_CHOSEN))

        and: "A flag is set in session informing that the user wants to register another second factor."
        1 * sessionManager.put(Attribute.ofFlag(REGISTRATION_OF_ANOTHER_SECOND_FACTOR))
    }

    def "should redirect to factor registration for another second factor if user has just authenticated with a previous second factor"()
    {
        given: "The user has just authenticated with a second factor."
        def sessionManager = getSessionManagerStubWithChosenSecondFactor("sms")

        and: "The user has previously chosen to register another second factor."
        sessionManager.remove(REGISTRATION_OF_ANOTHER_SECOND_FACTOR) >> Attribute.ofFlag(REGISTRATION_OF_ANOTHER_SECOND_FACTOR)
        sessionManager.get(ANOTHER_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(ANOTHER_SECOND_FACTOR_ATTRIBUTE, "email")

        and: "The user has a registered second factor."
        def user = getUserAttributes(["My iPhone 11": "sms"])
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("email")
        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)

        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        and: "The user is authenticated with the previously registered second factor."
        def sessions = authenticatedSessionsStubWithSession("sms")

        when: "When the action is applied."
        def response = action.apply(authenticationAttributes, sessions, "transactionId", null)

        then: "The user is redirected to the registration of the second factor."
        assert response instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = response.obligation
        assert obligation instanceof RequiredActionCompletion.RegisterUser
        def authenticator = obligation.authenticatorDescriptor
        authenticator.acr == "email"

        and: "The process is moved to next step."
        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, ANOTHER_NEW_SECOND_FACTOR_REGISTERED))
    }

    def "should redirect to factor registration for another second factor if user has previously authenticated with any previous second factor"()
    {
        given: "The user has started authentication flow with a second factor."
        def sessionManager = getSessionManagerStubWithoutChosenSecondFactor()

        and: "The user has previously chosen to register another second factor."
        sessionManager.remove(REGISTRATION_OF_ANOTHER_SECOND_FACTOR) >> Attribute.ofFlag(REGISTRATION_OF_ANOTHER_SECOND_FACTOR)
        sessionManager.get(ANOTHER_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(ANOTHER_SECOND_FACTOR_ATTRIBUTE, "email")

        and: "The user has a registered second factor."
        def user = getUserAttributes(["My iPhone 11": "sms"])
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("email")
        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)

        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        and: "The user is authenticated with the previously registered second factor."
        def sessions = authenticatedSessionsStubWithSession("sms")

        when: "When the action is applied."
        def response = action.apply(authenticationAttributes, sessions, "transactionId", null)

        then: "The user is redirected to the registration of the second factor."
        assert response instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = response.obligation
        assert obligation instanceof RequiredActionCompletion.RegisterUser
        def authenticator = obligation.authenticatorDescriptor
        authenticator.acr == "email"

        and: "The process is moved to next step."
        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, ANOTHER_NEW_SECOND_FACTOR_REGISTERED))
    }

    def "should redirect to factor registration for another second factor when factor is sms and user does not have a number if user has just authenticated with a previous second factor"()
    {
        given: "The user has just authenticated with a second factor."
        def sessionManager = getSessionManagerStubWithChosenSecondFactor("email")

        and: "The user has previously chosen to register sms as another second factor."
        sessionManager.remove(REGISTRATION_OF_ANOTHER_SECOND_FACTOR) >> Attribute.ofFlag(REGISTRATION_OF_ANOTHER_SECOND_FACTOR)
        sessionManager.get(ANOTHER_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(ANOTHER_SECOND_FACTOR_ATTRIBUTE, "acr-sms")

        and: "The user has a registered second factor, but no phone number."
        def user = getUserAttributes(["My email": "email"])
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("acr-sms")
        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)

        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        and: "The user is authenticated with the previously registered second factor."
        def sessions = authenticatedSessionsStubWithSession("email")

        when: "When the action is applied."
        def response = action.apply(authenticationAttributes, sessions, "transactionId", null)

        then: "The user is redirected to the registration of the second factor."
        assert response instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = response.obligation
        assert obligation instanceof RequiredActionCompletion.RegisterUser
        def authenticator = obligation.authenticatorDescriptor
        authenticator.acr == "acr-sms"

        and: "The process is moved to next step."
        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, ANOTHER_NEW_SECOND_FACTOR_REGISTERED))
    }

    def "should redirect to factor registration for another second factor when factor is sms and user does not have a number if user has previously authenticated with any previous second factor"()
    {
        given: "The user is at the start of the authentication flow with a second factor."
        def sessionManager = getSessionManagerStubWithoutChosenSecondFactor()

        and: "The user has previously chosen to register sms as another second factor."
        sessionManager.remove(REGISTRATION_OF_ANOTHER_SECOND_FACTOR) >> Attribute.ofFlag(REGISTRATION_OF_ANOTHER_SECOND_FACTOR)
        sessionManager.get(ANOTHER_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(ANOTHER_SECOND_FACTOR_ATTRIBUTE, "acr-sms")

        and: "The user has a registered second factor but does not have a phone number."
        def user = getUserAttributes(["My private email": "email"])
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("acr-sms")
        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)

        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        and: "The user is authenticated with the previously registered second factor."
        def sessions = authenticatedSessionsStubWithSession("email")

        when: "When the action is applied."
        def response = action.apply(authenticationAttributes, sessions, "transactionId", null)

        then: "The user is redirected to the registration of the second factor."
        assert response instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = response.obligation
        assert obligation instanceof RequiredActionCompletion.RegisterUser
        def authenticator = obligation.authenticatorDescriptor
        authenticator.acr == "acr-sms"

        and: "The process is moved to next step."
        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, ANOTHER_NEW_SECOND_FACTOR_REGISTERED))
    }

    def "should continue factor registration for another second factor when factor is {} and user does not have a number if user has just authenticated with a previous second factor"(String acr, Map<String, String> expectedSecondFactors)
    {
        given: "The user has just authenticated with a second factor."
        def sessionManager = getSessionManagerStubWithChosenSecondFactor("email")

        and: "The user has previously chosen to register one of the special factors as another second factor."
        sessionManager.remove(REGISTRATION_OF_ANOTHER_SECOND_FACTOR) >> Attribute.ofFlag(REGISTRATION_OF_ANOTHER_SECOND_FACTOR)
        sessionManager.get(ANOTHER_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(ANOTHER_SECOND_FACTOR_ATTRIBUTE, acr)

        and: "The user has a registered second factor and a phone number."
        def user = getUserAttributes(["My private email": "email"])
            .withPhoneNumbers(PhoneNumber.of("1234567", true))
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("acr-sms")
        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)

        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        and: "The user is authenticated with the previously registered second factor."
        def sessions = authenticatedSessionsStubWithSession("email")

        when: "When the action is applied."
        def result = action.apply(authenticationAttributes, sessions, "transactionId", null)

        then: "The second factor should be saved in the user's profile. The scratch codes should be untouched."

        1 * accountManager.updateAccount({
            it.contains("secondFactors")
            it.get("secondFactors").getValue().forEach { k,v -> expectedSecondFactors.containsKey(k) && expectedSecondFactors[k] == v }
            // The original profile in the test does not contain the codes, so they should still not be there.
            !it.contains("secondFactorCodes")
        })

        and: "The user should be redirected to the beginning of the flow."
        1 * sessionManager.remove(ANOTHER_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(ANOTHER_SECOND_FACTOR_ATTRIBUTE, acr)
        1 * sessionManager.remove(ANOTHER_SECOND_FACTOR_NAME) >> Attribute.of(ANOTHER_SECOND_FACTOR_NAME, "My second factor")
        assert result instanceof AuthenticationActionResult.SuccessAuthenticationActionResult

        where:
        acr         || expectedSecondFactors
        "acr-sms"   || ["My private email": "email", "My second factor": "acr-sms"]
        "acr-email" || ["My private email": "email", "My second factor": "acr-email"]
    }

    def "should continue factor registration for another second factor when factor is {} if user has previously authenticated with any previous second factor"(String acr, Map<String, String> expectedSecondFactors)
    {
        given: "The user is at the start of the authentication flow with a second factor."
        def sessionManager = getSessionManagerStubWithoutChosenSecondFactor()

        and: "The user has previously chosen to register one of the special authenticators as another second factor."
        sessionManager.remove(REGISTRATION_OF_ANOTHER_SECOND_FACTOR) >> Attribute.ofFlag(REGISTRATION_OF_ANOTHER_SECOND_FACTOR)
        sessionManager.get(ANOTHER_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(ANOTHER_SECOND_FACTOR_ATTRIBUTE, acr)

        and: "The user has a registered second factor and phone numbers."
        def user = getUserAttributes(["My private email": "email"])
            .withPhoneNumbers(PhoneNumber.of("1234567", true))
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor(acr)
        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)

        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        and: "The user is authenticated with the previously registered second factor."
        def sessions = authenticatedSessionsStubWithSession("email")

        when: "When the action is applied."
        def result = action.apply(authenticationAttributes, sessions, "transactionId", null)

        then: "The second factor should be saved in the user's profile. The scratch codes should be untouched."

        1 * accountManager.updateAccount({
            it.contains("secondFactors")
            it.get("secondFactors").getValue().forEach { k,v -> expectedSecondFactors.containsKey(k) && expectedSecondFactors[k] == v }
            // The original profile in the test does not contain the codes, so they should still not be there.
            !it.contains("secondFactorCodes")
        })

        and: "The user should be redirected to the beginning of the flow."
        1 * sessionManager.remove(ANOTHER_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(ANOTHER_SECOND_FACTOR_ATTRIBUTE, acr)
        1 * sessionManager.remove(ANOTHER_SECOND_FACTOR_NAME) >> Attribute.of(ANOTHER_SECOND_FACTOR_NAME, "My second factor")
        assert result instanceof AuthenticationActionResult.SuccessAuthenticationActionResult

        where:
        acr         || expectedSecondFactors
        "acr-sms"   || ["My private email": "email", "My second factor": "acr-sms"]
        "acr-email" || ["My private email": "email", "My second factor": "acr-email"]
    }

    def "should register another second factor and redirect to successful authentication when registration of another second factor completed"()
    {
        given: "The user wants to register another second factor."
        def sessionManager = Mock(SessionManager)
        sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, ANOTHER_NEW_SECOND_FACTOR_REGISTERED)
        sessionManager.remove(ANOTHER_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(ANOTHER_SECOND_FACTOR_ATTRIBUTE, "email")
        sessionManager.remove(ANOTHER_SECOND_FACTOR_NAME) >> Attribute.of(ANOTHER_SECOND_FACTOR_NAME, "My private email")
        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "transactionId")

        and: "The user is registered, has already a second factor and authenticator exists."
        def user = getUserAttributes(["My iPhone 11": "sms"], true)
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("email")

        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)

        def action = new OptInMFAAuthenticationAction(configuration, new ScratchCodeGenerator(configuration))

        and: "The user is authenticated with an existing second factor"
        def authenticatedSessions = authenticatedSessionsStubWithSession("sms")

        def secondFactors = ["My iPhone 11": "sms", "My private email": "email"] as Map
        def scratchCodes = scratchCodeGenerator.hashedCodes()

        when: "The authentication action is called"
        def result = action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then: "The second factor should be added to the user's profile and the scratch codes should not be regenerated."
        1 * accountManager.updateAccount({
            it.contains("secondFactors")
            it.get("secondFactors").getValue().size() == 2
            it.get("secondFactors").getValue().forEach { k,v -> secondFactors.containsKey(k) && secondFactors[k] == v }
            it.contains("secondFactorCodes")
            it.get("secondFactorCodes").size() == 10
            // Scratch codes in user profile are generated with test generator, but the action gets a "real" generator.
            // In the resulting profile the user should still have the codes from the test generator, that's how we know
            // the codes where not changed. This trick is used because it's hard to otherwise mock a Managed Object.
            it.get("secondFactorCodes").forEach { code -> scratchCodes.contains(code.getValue()) }
        })

        and: "The authentication process should be successful."
        assert result instanceof AuthenticationActionResult.SuccessAuthenticationActionResult
    }

    def "should throw Bad Request exception when trying to register a second factor with invalid scratch code"()
    {
        given: "The user wants to register a new second factor with a scratch code."
        def sessionManager = Mock(SessionManager)
        sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_CHOSEN)
        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "transactionId")
        sessionManager.get(EMERGENCY_REGISTRATION_OF_SECOND_FACTOR) >> Attribute.ofFlag(EMERGENCY_REGISTRATION_OF_SECOND_FACTOR)


        and: "The entered scratch code is wrong."
        sessionManager.remove(SCRATCH_CODE) >> Attribute.of(SCRATCH_CODE, "wrongCode")

        and: "The user is registered."
        def user = getUserAttributes(["My iPhone 11": "sms"], true)
        def accountManager = getAccountManagerStubReturningUser(user)
        def exceptionFactory = Mock(ExceptionFactory)
        def configuration = new TestActionConfiguration(accountManager, sessionManager, exceptionFactory)

        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        def sessions = authenticatedSessionsStubWithoutSessions()

        when: "The action is called."
        action.apply(authenticationAttributes, sessions, "transactionId", null)

        then:
        thrown RuntimeException
        1 * exceptionFactory.badRequestException(ErrorCode.INVALID_INPUT) >> new RuntimeException()
    }

    def "should redirect to registration of a new second factor when scratch code is valid and remove the code from user's account"()
    {
        given: "The user wants to register a new second factor with a scratch code."
        def sessionManager = Mock(SessionManager)
        sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_CHOSEN)
        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "transactionId")
        sessionManager.get(EMERGENCY_REGISTRATION_OF_SECOND_FACTOR) >> Attribute.ofFlag(EMERGENCY_REGISTRATION_OF_SECOND_FACTOR)

        sessionManager.get(CHOSEN_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(ANOTHER_SECOND_FACTOR_ATTRIBUTE, "email")

        and: "The entered scratch code is valid."
        sessionManager.remove(SCRATCH_CODE) >> Attribute.of(SCRATCH_CODE, "1")

        and: "The user is registered and authenticator exists."
        def user = getUserAttributes(["My iPhone": "sms"], true)
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("email")
        def authenticatedSessions = authenticatedSessionsStubWithoutSessions()

        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        def hashedCode = DigestUtils.sha256Hex("1")

        when: "The authentication action is called"
        def result = action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then: "The user should be redirected to registration action of the chosen authenticator"
        assert result instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = result.obligation
        assert obligation instanceof RequiredActionCompletion.RegisterUser

        def authenticatorDescriptor = obligation.authenticatorDescriptor
        authenticatorDescriptor.getAcr() == "email"

        and: "The state should be moved to next step."
        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_REGISTERED))

        and: "The used scratch code should be removed from user's profile."
        1 * accountManager.updateAccount({
            it.contains("secondFactorCodes")
            it.get("secondFactorCodes").size() == 9
            !it.get("secondFactorCodes").contains(hashedCode)
        })
    }

    def "when processing registered second factor confirmed with a scratch code, should update list of second factors and not issue new codes, then redirect to start of process"()
    {
        given: "The user has just registered a second factor using a scratch code."
        def sessionManager = Mock(SessionManager)
        sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_REGISTERED)
        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "transactionId")
        sessionManager.remove(CHOSEN_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(CHOSEN_SECOND_FACTOR_ATTRIBUTE, "email")
        sessionManager.remove(CHOSEN_SECOND_FACTOR_NAME) >> Attribute.of(CHOSEN_SECOND_FACTOR_NAME, "My private mail")
        sessionManager.get(EMERGENCY_REGISTRATION_OF_SECOND_FACTOR) >> Attribute.ofFlag(EMERGENCY_REGISTRATION_OF_SECOND_FACTOR)

        and: "The user is registered and authenticator exists"
        def user = getUserAttributes(["My iPhone": "sms"], true)
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("email")
        def authenticatedSessions = authenticatedSessionsStubWithoutSessions()
        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)

        def action = new OptInMFAAuthenticationAction(configuration, new ScratchCodeGenerator(configuration))

        def secondFactors = ["My iPhone": "sms", "My private mail": "email"] as Map
        def scratchCodes = scratchCodeGenerator.hashedCodes()

        when: "The authentication action is called"
        def result = action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then: "The list of second factors should be updated with the new one and hashed scratch codes should not be updated in the user profile."

        1 * accountManager.updateAccount({
            it.contains("secondFactors")
            it.get("secondFactors").getValue().size() == 2
            it.get("secondFactors").getValue().forEach { k,v -> secondFactors.containsKey(k) && secondFactors[k] == v }
            it.contains("secondFactorCodes")
            it.get("secondFactorCodes").size() == 10

            // Scratch codes in user profile are generated with test generator, but the action gets a "real" generator.
            // In the resulting profile the user should still have the codes from the test generator, that's how we know
            // the codes where not changed. This trick is used because it's hard to otherwise mock a Managed Object.
            it.get("secondFactorCodes").forEach { code -> scratchCodes.contains(code.getValue()) }
        })

        and: "The user should be redirected to the start of the opt-in-mfa action."
        assert result instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = result.obligation
        assert obligation instanceof RequiredActionCompletion.PromptUser

        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, NO_SECOND_FACTOR_CHOSEN))
        1 * sessionManager.remove(EMERGENCY_REGISTRATION_OF_SECOND_FACTOR)
    }

    def "should issue new scratch codes when registered a factor with the last available code"()
    {
        given: "The user has just registered a second factor using a scratch code."
        def sessionManager = Mock(SessionManager)
        sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_REGISTERED)
        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "transactionId")
        sessionManager.remove(CHOSEN_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(CHOSEN_SECOND_FACTOR_ATTRIBUTE, "email")
        sessionManager.remove(CHOSEN_SECOND_FACTOR_NAME) >> Attribute.of(CHOSEN_SECOND_FACTOR_NAME, "My private mail")
        sessionManager.get(EMERGENCY_REGISTRATION_OF_SECOND_FACTOR) >> Attribute.ofFlag(EMERGENCY_REGISTRATION_OF_SECOND_FACTOR)

        and: "The user is registered, but has no scratch codes left, and authenticator exists."
        def user = getUserAttributes(["My iPhone": "sms"])
            .with(Attribute.of(SECOND_FACTOR_CODES, MapAttributeValue.of([] as List)))
        def accountManager = getAccountManagerStubReturningUser(user)
        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("email")
        def authenticatedSessions = authenticatedSessionsStubWithoutSessions()
        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)

        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        def scratchCodes = scratchCodeGenerator.hashedCodes()

        when: "The authentication action is called"
        action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then: "The list of second factors should be updated with the new one and hashed scratch codes should not be updated in the user profile."
        1 * accountManager.updateAccount({
            it.contains("secondFactorCodes")
            it.get("secondFactorCodes").size() == 10
            it.get("secondFactorCodes").forEach { code -> scratchCodes.contains(code.getValue()) }
        })
    }

    def "should throw Bad Request exception if user trying to delete not their second factor"()
    {
        given: "The user has chosen a second factor to delete."
        def sessionManager = Mock(SessionManager)
        sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, SECOND_FACTOR_CHOSEN_TO_DELETE)
        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "transactionId")
        sessionManager.get(ANOTHER_SECOND_FACTOR_NAME) >> Attribute.of(ANOTHER_SECOND_FACTOR_NAME, "My private email")

        and: "The user does not have the chosen second factor."
        def user = getUserAttributes(["My iPhone 11": "sms"])
        def accountManager = getAccountManagerStubReturningUser(user)
        def exceptionFactory = Mock(ExceptionFactory)
        def configuration = new TestActionConfiguration(accountManager, sessionManager, exceptionFactory)

        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        def sessions = authenticatedSessionsStubWithoutSessions()

        when: "When the action is applied."
        action.apply(authenticationAttributes, sessions, "transactionId", null)

        then: "A bad request exception is thrown."
        thrown RuntimeException
        1 * exceptionFactory.badRequestException(ErrorCode.INVALID_INPUT)

        and: "The session is cleared"
        1 * sessionManager.remove(AUTHENTICATION_TRANSACTION)
        1 * sessionManager.remove(ANOTHER_SECOND_FACTOR_NAME)
    }

    def "should require authentication with second factor when trying to delete second factor"()
    {
        given: "The user has chosen a second factor to delete."
        def sessionManager = Mock(SessionManager)
        sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, SECOND_FACTOR_CHOSEN_TO_DELETE)
        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "transactionId")
        sessionManager.get(ANOTHER_SECOND_FACTOR_NAME) >> Attribute.of(ANOTHER_SECOND_FACTOR_NAME, "My iPhone 11")

        and: "The user has the chosen second factor."
        def user = getUserAttributes(["My iPhone 11": "sms"])
        def accountManager = getAccountManagerStubReturningUser(user)
        def exceptionFactory = Mock(ExceptionFactory)
        def configuration = new TestActionConfiguration(accountManager, sessionManager, exceptionFactory)

        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        and: "The user is not authenticated with any other second factor."
        def sessions = authenticatedSessionsStubWithoutSessions()

        when: "When the action is applied."
        def response = action.apply(authenticationAttributes, sessions, "transactionId", null)

        then: "The user is redirected to start of process (authenticate with a second factor)."
        assert response instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = response.obligation
        assert obligation instanceof RequiredActionCompletion.PromptUser
        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, NO_SECOND_FACTOR_CHOSEN))

        and: "A flag is set in session informing that the user wants to delete a second factor."
        1 * sessionManager.put(Attribute.ofFlag(DELETION_OF_SECOND_FACTOR))
    }

    def "should delete second factor and redirect to start of process"()
    {
        given: "The user has chosen a second factor to delete."
        def sessionManager = Mock(SessionManager)
        sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, SECOND_FACTOR_CHOSEN)
        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "transactionId")
        sessionManager.remove(ANOTHER_SECOND_FACTOR_NAME) >> Attribute.of(ANOTHER_SECOND_FACTOR_NAME, "My iPhone 11")
        sessionManager.remove(CHOSEN_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(CHOSEN_SECOND_FACTOR_ATTRIBUTE, "email1")
        sessionManager.remove(DELETION_OF_SECOND_FACTOR) >> Attribute.ofFlag(DELETION_OF_SECOND_FACTOR)

        and: "The user has the chosen second factor."
        def user = getUserAttributes(["My iPhone 11": "sms", "My private email": "email1"])
        def accountManager = getAccountManagerStubReturningUser(user)
        def exceptionFactory = Mock(ExceptionFactory)
        def configuration = new TestActionConfiguration(accountManager, sessionManager, exceptionFactory)

        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        and: "The user is authenticated with an existing second factor"
        def authenticatedSessions = authenticatedSessionsStubWithSession("email1")

        def resultingSecondFactors = ["My private email": "email1"] as Map

        when: "The authentication action is called"
        def result = action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then: "The second factor should be removed from the user's profile."
        1 * accountManager.updateAccount({
            it.contains("secondFactors")
            it.get("secondFactors").getValue().size() == 1
            it.get("secondFactors").getValue().forEach { k,v -> resultingSecondFactors.containsKey(k) && resultingSecondFactors[k] == v }
        })

        and: "The user should be redirected to start of process."
        assert result instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = result.obligation
        assert obligation instanceof RequiredActionCompletion.PromptUser
        1 * sessionManager.put(Attribute.ofFlag(FORCE_SHOW_LIST_OF_SECOND_FACTORS))
        1 * sessionManager.remove(FORCE_SHOW_LIST_OF_SECOND_FACTORS) >> Attribute.ofFlag(FORCE_SHOW_LIST_OF_SECOND_FACTORS)
        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, NO_SECOND_FACTOR_CHOSEN))
    }

    def "should delete second factor and redirect to start of process if already authenticated with second factor"()
    {
        given: "The user has chosen a second factor to delete."
        def sessionManager = Mock(SessionManager)
        sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, NO_SECOND_FACTOR_CHOSEN)
        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "transactionId")
        sessionManager.remove(ANOTHER_SECOND_FACTOR_NAME) >> Attribute.of(ANOTHER_SECOND_FACTOR_NAME, "My iPhone 11")
        sessionManager.remove(DELETION_OF_SECOND_FACTOR) >> Attribute.ofFlag(DELETION_OF_SECOND_FACTOR)

        and: "The user has the chosen second factor."
        def user = getUserAttributes(["My iPhone 11": "sms", "My private email": "email1"])
        def accountManager = getAccountManagerStubReturningUser(user)
        def exceptionFactory = Mock(ExceptionFactory)
        def configuration = new TestActionConfiguration(accountManager, sessionManager, exceptionFactory)

        def action = new OptInMFAAuthenticationAction(configuration, scratchCodeGenerator)

        and: "The user is authenticated with an existing second factor"
        def authenticatedSessions = authenticatedSessionsStubWithSession("email1")

        def resultingSecondFactors = ["My private email": "email1"] as Map

        when: "The authentication action is called"
        def result = action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then: "The second factor should be removed from the user's profile."
        1 * accountManager.updateAccount({
            it.contains("secondFactors")
            it.get("secondFactors").getValue().size() == 1
            it.get("secondFactors").getValue().forEach { k,v -> resultingSecondFactors.containsKey(k) && resultingSecondFactors[k] == v }
        })

        and: "The user should be redirected to start of process."
        assert result instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        def obligation = result.obligation
        assert obligation instanceof RequiredActionCompletion.PromptUser
        1 * sessionManager.put(Attribute.ofFlag(FORCE_SHOW_LIST_OF_SECOND_FACTORS))
        2 * sessionManager.remove(FORCE_SHOW_LIST_OF_SECOND_FACTORS) >>> [null, Attribute.ofFlag(FORCE_SHOW_LIST_OF_SECOND_FACTORS)]
        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, NO_SECOND_FACTOR_CHOSEN))
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
        sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_CHOSEN)
        sessionManager.get(CHOSEN_SECOND_FACTOR_ATTRIBUTE) >> Attribute.of(CHOSEN_SECOND_FACTOR_ATTRIBUTE, chosenFactor)
        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "transactionId")

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
            sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, SECOND_FACTOR_CHOSEN)
            sessionManager.remove(CHOSEN_SECOND_FACTOR_ATTRIBUTE) >> secondFactor
        }
        else if (isFirstSecondFactorRegistered)
        {
            sessionManager.remove(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_REGISTERED)
            sessionManager.remove(CHOSEN_SECOND_FACTOR_ATTRIBUTE) >> secondFactor
        }
        else
        {
            sessionManager.remove(OPT_IN_MFA_STATE) >> null
        }

        sessionManager.get(AUTHENTICATION_TRANSACTION) >> Attribute.of(AUTHENTICATION_TRANSACTION, "transactionId")

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
        def authenticator = Stub(AuthenticatorDescriptor)
        authenticator.getAcr() >> acr

        def descriptor = Stub(AuthenticatorDescriptorFactory)
        descriptor.getAuthenticatorDescriptors(acr) >> NonEmptyList.of(authenticator)
        descriptor
    }

    private def getUserAttributes(secondFactors = null, includeScratchCodes = false)
    {
        def user = AccountAttributes.fromMap(["id": "1234", "subject": username])
        if (secondFactors)
        {
            user = AccountAttributes.fromMap(["id": "1234", "subject": username, "secondFactors": secondFactors])
        }

        if (includeScratchCodes) {
            user = user.with(Attribute.of("secondFactorCodes", ListAttributeValue.of(scratchCodeGenerator.hashedCodes())))
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

    static class TestScratchCodeGenerator extends ScratchCodeGenerator
    {
        TestScratchCodeGenerator() {
            super(null)
        }

        @Override
        List<String> generateScratchCodes() {
            return (1..10).stream().map {it.toString()}.collect(Collectors.toList())
        }

        List<String> hashedCodes() {
            (1..10).stream().map { DigestUtils.sha256Hex(it.toString()) }.collect(Collectors.toList())
        }
    }
}
