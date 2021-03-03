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
import se.curity.identityserver.sdk.attribute.Attribute
import se.curity.identityserver.sdk.attribute.MapAttributeValue
import se.curity.identityserver.sdk.authenticationaction.completions.ActionCompletionResult
import se.curity.identityserver.sdk.errors.AuthenticatorNotConfiguredException
import se.curity.identityserver.sdk.service.ExceptionFactory
import se.curity.identityserver.sdk.service.SessionManager
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptor
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptorFactory
import se.curity.identityserver.sdk.web.Request
import se.curity.identityserver.sdk.web.Response
import se.curity.identityserver.sdk.web.cookie.Cookie
import se.curity.identityserver.sdk.web.cookie.RequestCookies
import spock.lang.Shared
import spock.lang.Specification

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.AVAILABLE_SECOND_FACTORS_ATTRIBUTE
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.CHOSEN_SECOND_FACTOR_ATTRIBUTE
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.REMEMBER_CHOICE_COOKIE_NAME

class OptInMFAuthenticationActionHandlerTest extends Specification {

    @Shared def sessionManager = Stub(SessionManager)
    def configuration = new TestActionConfiguration(null, null, null)

    def setupSpec() {
        sessionManager.remove(AVAILABLE_SECOND_FACTORS_ATTRIBUTE) >> Attribute.of(
                AVAILABLE_SECOND_FACTORS_ATTRIBUTE,
                MapAttributeValue.of(["My email": "email1", "My sms": "sms1"]))
    }

    def "should not allow POST requests"()
    {
        given:
        def exceptionFactory = Mock(ExceptionFactory)
        def handler = new OptInMFAuthenticationActionHandler(null, null, null, exceptionFactory)

        when:
        handler.post(null, null)

        then:
        1 * exceptionFactory.methodNotAllowed() >> new RuntimeException()
        thrown RuntimeException
    }

    def "should prepare list of authenticators and display view"()
    {
        given:
        def factory = Mock(AuthenticatorDescriptorFactory)
        def handler = new OptInMFAuthenticationActionHandler(factory, sessionManager, configuration, null)

        def response = Mock(Response)

        def request = Stub(Request)
        def cookieJar = Stub(RequestCookies)
        cookieJar.getFirst(REMEMBER_CHOICE_COOKIE_NAME) >> null
        request.getCookies() >> cookieJar

        def authenticatorList = NonEmptyList.of(Stub(AuthenticatorDescriptor))
        when:
        def result = handler.get(request, response)

        then:
        !result.isPresent()
        1 * factory.getAuthenticatorDescriptors("email1") >> authenticatorList
        1 * factory.getAuthenticatorDescriptors("sms1") >> authenticatorList
        1 * response.putViewData("authenticators", _ as Map, _)
    }

    def "should remove authenticator from rendered list if authenticator no longer present in system"()
    {
        given:
        def factory = Mock(AuthenticatorDescriptorFactory)
        def handler = new OptInMFAuthenticationActionHandler(factory, sessionManager, configuration, null)

        def response = Mock(Response)

        def request = Stub(Request)
        def cookieJar = Stub(RequestCookies)
        cookieJar.getFirst(REMEMBER_CHOICE_COOKIE_NAME) >> null
        request.getCookies() >> cookieJar

        def authenticatorList = NonEmptyList.of(Stub(AuthenticatorDescriptor))

        when:
        def result = handler.get(request, response)

        then:
        noExceptionThrown()
        !result.isPresent()
        1 * factory.getAuthenticatorDescriptors("email1") >> authenticatorList
        1 * factory.getAuthenticatorDescriptors("sms1") >> { throw new AuthenticatorNotConfiguredException("") }
        // The resulting authenticator map should only have 1 element
        1 * response.putViewData("authenticators", { it.size() == 1 }, _)
    }

    def "should set session variables and continue flow when user has rememberChoice cookie set"()
    {
        given:
        def sessionManager = Mock(SessionManager)
        sessionManager.remove(AVAILABLE_SECOND_FACTORS_ATTRIBUTE) >> Attribute.of(
                AVAILABLE_SECOND_FACTORS_ATTRIBUTE,
                MapAttributeValue.of(["My email": "email1", "My sms": "sms1"]))
        def factory = Mock(AuthenticatorDescriptorFactory)
        def handler = new OptInMFAuthenticationActionHandler(factory, sessionManager, configuration, null)

        def response = Mock(Response)

        def request = Stub(Request)
        def cookieJar = Stub(RequestCookies)
        def cookie = Stub(Cookie)
        cookie.getValue() >> "email1"

        cookieJar.getFirst(REMEMBER_CHOICE_COOKIE_NAME) >> cookie
        request.getCookies() >> cookieJar

        def authenticatorList = NonEmptyList.of(Stub(AuthenticatorDescriptor))

        when:
        def result = handler.get(request, response)

        then:
        result.isPresent()
        def actionResult = result.get()
        actionResult instanceof ActionCompletionResult.CompletedActionCompletionResult

        1 * factory.getAuthenticatorDescriptors("email1") >> authenticatorList
        1 * factory.getAuthenticatorDescriptors("sms1") >> authenticatorList

        1 * sessionManager.put({ it.getName().getValue() == CHOSEN_SECOND_FACTOR_ATTRIBUTE
            it.getValue().toString() == "email1" })
        1 * sessionManager.put({ it.getName().getValue() == IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE
            it.getValue() == [] as Collection })
        0 * response.putViewData("authenticators", _, _)
    }

    def "should display screen if rememberChoice cookie set but authenticator not available any more"()
    {
        given:
        def factory = Mock(AuthenticatorDescriptorFactory)
        def handler = new OptInMFAuthenticationActionHandler(factory, sessionManager, configuration, null)

        def response = Mock(Response)

        def request = Stub(Request)
        def cookieJar = Stub(RequestCookies)
        def cookie = Stub(Cookie)
        cookie.getValue() >> "email1"

        cookieJar.getFirst(REMEMBER_CHOICE_COOKIE_NAME) >> cookie
        request.getCookies() >> cookieJar

        def authenticatorList = NonEmptyList.of(Stub(AuthenticatorDescriptor))
        when:
        def result = handler.get(request, response)

        then:
        !result.isPresent()

        1 * factory.getAuthenticatorDescriptors("email1") >> { throw new AuthenticatorNotConfiguredException("") }
        1 * factory.getAuthenticatorDescriptors("sms1") >> authenticatorList

        1 * response.putViewData("authenticators", { it.size() == 1 }, _)
    }
}
