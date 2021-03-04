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

import se.curity.identityserver.sdk.plugin.ManagedObject;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.apache.commons.lang3.RandomStringUtils.randomNumeric;

public class ScratchCodeGenerator extends ManagedObject<OptInMFAAuthenticationActionConfig>
{
    public ScratchCodeGenerator(OptInMFAAuthenticationActionConfig configuration)
    {
        super(configuration);
    }

    public List<String> generateScratchCodes()
    {
        return IntStream.range(0, 10).mapToObj(
            (i) -> randomAlphabetic(15) + "-" + randomNumeric(6) + "-" + randomAlphabetic(5)
        ).collect(Collectors.toList());
    }
}
