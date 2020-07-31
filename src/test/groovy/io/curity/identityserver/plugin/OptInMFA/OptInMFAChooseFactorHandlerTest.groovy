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

import se.curity.identityserver.sdk.service.SessionManager
import se.curity.identityserver.sdk.web.Request
import se.curity.identityserver.sdk.web.Response
import se.curity.identityserver.sdk.web.cookie.ResponseCookies
import se.curity.identityserver.sdk.web.cookie.StandardResponseCookie
import spock.lang.Specification

import java.time.Duration

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.CHOSEN_SECOND_FACTOR_ATTRIBUTE
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE

class OptInMFAChooseFactorHandlerTest extends Specification {

    def configuration = new TestActionConfiguration(null, null, null)

    def "should throw exception when secondFactor parameter missing in request"()
    {
        given:
        def request = Stub(Request)
        request.getFormParameterValueOrError("secondFactor") >> null

        when:
        new ChooseFactorPostRequestModel(request)

        then:
        thrown MissingSecondFactorParameterException
    }

    def "should set session variables and not set cookie when option in form not set"()
    {
        given:
        def sessionManager = Mock(SessionManager)

        def cookieJar = Mock(ResponseCookies)
        def response = Stub(Response)
        response.cookies() >> cookieJar

        def request = Stub(Request)
        request.getFormParameterValueOrError("secondFactor") >> "email1"
        request.getFormParameterValueOrError("rememberChoice") >> null
        def requestModel = new ChooseFactorPostRequestModel(request)

        def handler = new OptInMFAChooseFactorHandler(sessionManager, null, configuration)

        when:
        handler.post(requestModel, response)

        then:
        1 * sessionManager.put({ it.getValue().toString() == "email1"; it.getName().getValue() == CHOSEN_SECOND_FACTOR_ATTRIBUTE })
        1 * sessionManager.put({ it.getName().getValue() == IS_SECOND_FACTOR_CHOSEN_ATTRIBUTE; it.getValue() == [] as Collection })
        0 * cookieJar.add(_)
    }

    def "should set rememberChoice cookie if option in form set"()
    {
        given:
        def sessionManager = Stub(SessionManager)

        def cookieJar = Mock(ResponseCookies)
        def response = Stub(Response)
        response.cookies() >> cookieJar

        def request = Stub(Request)
        request.getParameterValueOrError("rememberChoice") >> "on"
        def requestModel = new ChooseFactorPostRequestModel(request)

        def handler = new OptInMFAChooseFactorHandler(sessionManager, null, configuration)

        when:
        handler.post(requestModel, response)

        then:
        1 * cookieJar.add({ StandardResponseCookie cookie -> cookie.maxAge.get() == Duration.ofDays(30); })
    }
}
