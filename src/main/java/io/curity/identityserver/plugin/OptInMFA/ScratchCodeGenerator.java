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
