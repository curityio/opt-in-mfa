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
package io.curity.identityserver.plugin.OptInMFA;

public enum OptInMFAState
{
    NO_SECOND_FACTOR_CHOSEN,
    SECOND_FACTOR_CHOSEN,
    FIRST_CHOICE_OF_SECOND_FACTOR,
    FIRST_SECOND_FACTOR_CHOSEN,
    FIRST_SECOND_FACTOR_REGISTERED,
    CONFIRM_SCRATCH_CODES,
    SCRATCH_CODES_CONFIRMED,
    ANOTHER_NEW_SECOND_FACTOR_CHOSEN,
    ANOTHER_NEW_SECOND_FACTOR_REGISTERED
}
