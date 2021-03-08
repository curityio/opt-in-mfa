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
package io.curity.identityserver.plugin.OptInMFA

import io.curity.identityserver.plugin.OptInMFA.handler.OptInMFAEmergencyRegisterFactorHandler
import io.curity.identityserver.plugin.OptInMFA.model.EmergencyFactorRegistrationRequestModel
import se.curity.identityserver.sdk.NonEmptyList
import se.curity.identityserver.sdk.attribute.Attribute
import se.curity.identityserver.sdk.authenticationaction.completions.ActionCompletionResult
import se.curity.identityserver.sdk.errors.AuthenticatorNotConfiguredException
import se.curity.identityserver.sdk.service.SessionManager
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptor
import se.curity.identityserver.sdk.service.authenticationaction.AuthenticatorDescriptorFactory
import se.curity.identityserver.sdk.web.Request
import se.curity.identityserver.sdk.web.Response
import spock.lang.Shared
import spock.lang.Specification

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.CHOSEN_SECOND_FACTOR_ATTRIBUTE
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.CHOSEN_SECOND_FACTOR_NAME
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.OPT_IN_MFA_STATE
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.EMERGENCY_REGISTRATION_OF_SECOND_FACTOR
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.SCRATCH_CODE
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.FIRST_SECOND_FACTOR_CHOSEN
import static io.curity.identityserver.plugin.OptInMFA.OptInMFAState.NO_SECOND_FACTOR_CHOSEN

class OptInMFEmergencyRegisterHandlerTest extends Specification {

    @Shared def sessionManager = Stub(SessionManager)
    def configuration = new TestActionConfiguration()

    def setupSpec() {
        sessionManager.get(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, NO_SECOND_FACTOR_CHOSEN)
    }

    def "should prepare list of authenticators and display view"()
    {
        given: "All the necessary object are prepared."
        def factory = Mock(AuthenticatorDescriptorFactory)
        def handler = new OptInMFAEmergencyRegisterFactorHandler(factory, sessionManager, configuration, null)

        def request = Stub(Request)
        def model = new EmergencyFactorRegistrationRequestModel(request)
        def response = Mock(Response)

        def authenticatorList = NonEmptyList.of(Stub(AuthenticatorDescriptor))

        when: "The get endpoint is called."
        def result = handler.get(model, response)

        then: "The list of authenticators is prepared and displayed."
        !result.isPresent()
        1 * factory.getAuthenticatorDescriptors("acr1") >> authenticatorList
        1 * factory.getAuthenticatorDescriptors("acr2") >> authenticatorList
        1 * response.putViewData("availableAuthenticators", _ as List, _)
    }

    def "should remove authenticator from rendered list if authenticator no longer present in system"()
    {
        given: "All the necessary object are prepared."
        def factory = Mock(AuthenticatorDescriptorFactory)
        def handler = new OptInMFAEmergencyRegisterFactorHandler(factory, sessionManager, configuration, null)

        def response = Mock(Response)
        def request = Stub(Request)
        def model = new EmergencyFactorRegistrationRequestModel(request)

        def authenticatorList = NonEmptyList.of(Stub(AuthenticatorDescriptor))

        when: "The get endpoint is called."
        def result = handler.get(model, response)

        then: "No exception should be thrown to the user and the resulting list should have only one element."
        noExceptionThrown()
        !result.isPresent()
        1 * factory.getAuthenticatorDescriptors("acr1") >> authenticatorList
        1 * factory.getAuthenticatorDescriptors("acr2") >> { throw new AuthenticatorNotConfiguredException("") }
        1 * response.putViewData("availableAuthenticators", { it.size() == 1 }, _)
    }

    def "should set user's choice in session and continue with the flow"()
    {
        given: "The user has chosen a new factor to register."
        def sessionManager = Mock(SessionManager)
        sessionManager.get(OPT_IN_MFA_STATE) >> Attribute.of(OPT_IN_MFA_STATE, NO_SECOND_FACTOR_CHOSEN)

        def response = Stub(Response)
        def request = Stub(Request)
        request.getFormParameterValueOrError("scratchCode") >> "abcdef"
        request.getFormParameterValueOrError("secondFactor") >> "email1"
        request.getFormParameterValueOrError("secondFactorName") >> "My private email"
        def requestModel = new EmergencyFactorRegistrationRequestModel(request)

        def factory = Mock(AuthenticatorDescriptorFactory)
        def handler = new OptInMFAEmergencyRegisterFactorHandler(factory, sessionManager, configuration, null)

        when: "The post endpoint is called."
        def result = handler.post(requestModel, response)

        then: "Information about the chosen factor are set in session."
        1 * sessionManager.put({ it.getValue().toString() == "email1"; it.getName().getValue() == CHOSEN_SECOND_FACTOR_ATTRIBUTE })
        1 * sessionManager.put(Attribute.of(CHOSEN_SECOND_FACTOR_NAME, "My private email"))
        1 * sessionManager.put(Attribute.of(SCRATCH_CODE, "abcdef"))

        and: "The process is moved to the next step with the emergency flag."
        1 * sessionManager.put(Attribute.of(OPT_IN_MFA_STATE, FIRST_SECOND_FACTOR_CHOSEN))
        1 * sessionManager.put(Attribute.ofFlag(EMERGENCY_REGISTRATION_OF_SECOND_FACTOR))

        and: "The user is redirected to the action again."
        assert result.isPresent()
        assert result.get() instanceof ActionCompletionResult.CompletedActionCompletionResult
    }
}
