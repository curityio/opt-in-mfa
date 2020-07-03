package io.curity.identityserver.plugin.OptInMFA

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

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.CHOSEN_SECOND_FACTOR_ATTRIBUTE

final class OptInMFAAuthenticationActionTest extends Specification {

    private def username = "john"
    private def authenticationAttributes = AuthenticationAttributes.of(username, ContextAttributes.empty())
    @Shared private def authenticator = Stub(AuthenticatorDescriptor)

    def setupSpec()
    {
        authenticator.getAcr() >> "email"
    }

    def "should fail authentication when user does not have secondary factors"()
    {
        // TODO: this should eventually redirect to registration
        given:
        def sessionManager = getSessionManagerStubWithoutChosenSecondFactor()

        def user = getUserAttributes()
        def accountManager = getAccountManagerStubReturningUser(user)

        def configuration = new TestActionConfiguration(accountManager, null, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration)

        when:
        def result = action.apply(authenticationAttributes, null, "transactionId", null)

        then:
        result instanceof AuthenticationActionResult.FailedAuthenticationActionResult
    }

    def "should return pending result when user hasn't chosen a secondary factor yet"()
    {
        given:
        def sessionManager = getSessionManagerStubWithoutChosenSecondFactor()

        def user = getUserAttributes(["My email": "email"])
        def accountManager = getAccountManagerStubReturningUser(user)

        def configuration = new TestActionConfiguration(accountManager, null, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration)

        when:
        def result = action.apply(authenticationAttributes, null, "transactionId", null)

        then:
        result instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult
        ((AuthenticationActionResult.PendingCompletionAuthenticationActionResult) result).obligation instanceof RequiredActionCompletion.PromptUser
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
        def action = new OptInMFAAuthenticationAction(configuration)

        when:
        def result = action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then:
        result instanceof AuthenticationActionResult.PendingCompletionAuthenticationActionResult

        def obligation = ((AuthenticationActionResult.PendingCompletionAuthenticationActionResult) result).obligation
        obligation instanceof RequiredActionCompletion.AuthenticateUser

        def authenticatorDescriptor = ((RequiredActionCompletion.AuthenticateUser) obligation).authenticatorDescriptor
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
        def action = new OptInMFAAuthenticationAction(configuration)

        when:
        action.apply(authenticationAttributes, null, "transactionId", null)

        then:
        thrown IllegalStateException
    }

    def "should successfully complete action if secondary factor chosen and user already logged in using that factor"()
    {
        given:
        def sessionManager = getSessionManagerStubWithChosenSecondFactor("email")

        def user = getUserAttributes(["My email": "email"])
        def accountManager = getAccountManagerStubReturningUser(user)


        def descriptorFactory = authenticatorDescriptorFactoryStubReturningDescriptor("email")

        def authenticatedSessions = authenticatedSessionsStubWithSession("email")

        def configuration = new TestActionConfiguration(accountManager, descriptorFactory, sessionManager)
        def action = new OptInMFAAuthenticationAction(configuration)

        when:
        def result = action.apply(authenticationAttributes, authenticatedSessions, "transactionId", null)

        then:
        result instanceof AuthenticationActionResult.SuccessAuthenticationActionResult
    }

    private def getSessionManagerStubWithoutChosenSecondFactor()
    {
        getSessionManagerStub(false, null)
    }

    private def getSessionManagerStubWithChosenSecondFactor(String chosenFactor)
    {
        getSessionManagerStub(true, Attribute.of(CHOSEN_SECOND_FACTOR_ATTRIBUTE, chosenFactor))
    }

    private def getSessionManagerStub(isSecondFactorChosen, secondFactor)
    {
        def sessionManager = Mock(SessionManager)

        if (isSecondFactorChosen) {
            sessionManager.get(IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE) >> Attribute.ofFlag(IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE)
            sessionManager.get(CHOSEN_SECOND_FACTOR_ATTRIBUTE) >> secondFactor
        } else {
            sessionManager.get(IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE) >> null
        }

        sessionManager
    }

    private def authenticatorDescriptorFactoryStubThrowingError(id)
    {
        def descriptor = Stub(AuthenticatorDescriptorFactory)
        descriptor.getAuthenticatorDescriptor(id) >> { throw new AuthenticatorNotConfiguredException("Not configured") }
        descriptor
    }

    private def authenticatorDescriptorFactoryStubReturningDescriptor(id)
    {
        def descriptor = Stub(AuthenticatorDescriptorFactory)
        descriptor.getAuthenticatorDescriptor(id) >> authenticator
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
        def accountManager = Stub(AccountManager)
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

    private class TestActionConfiguration implements OptInMFAAuthenticationActionConfig
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
            return _accountManager
        }

        @Override
        AuthenticatorDescriptorFactory getAuthenticatorDescriptorFactory() {
            return _authenticatorDescriptorFactory
        }

        @Override
        SessionManager getSessionManager() {
            return _sessionManager
        }

        @Override
        String id() {
            return ""
        }
    }
}
