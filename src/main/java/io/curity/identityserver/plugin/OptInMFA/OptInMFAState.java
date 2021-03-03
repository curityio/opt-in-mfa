package io.curity.identityserver.plugin.OptInMFA;

import static io.curity.identityserver.plugin.OptInMFA.OptInMFAAuthenticationAction.ATTRIBUTE_PREFIX;

public enum OptInMFAState
{
    NO_SECOND_FACTOR_CHOSEN(ATTRIBUTE_PREFIX + "no-factor-chosen"),
    SECOND_FACTOR_CHOSEN(ATTRIBUTE_PREFIX + "is-second-factor-chosen"),
    FIRST_CHOICE_OF_SECOND_FACTOR(ATTRIBUTE_PREFIX + "is-first-choice-of-second-factor"),
    FIRST_SECOND_FACTOR_REGISTERED(ATTRIBUTE_PREFIX + "is-first-registered-second-factor"),
    SCRATCH_CODES_CONFIRMED(ATTRIBUTE_PREFIX + "scratch-codes-confirmed");

    private final String sessionKey;


    OptInMFAState(String sessionKey)
    {
        this.sessionKey = sessionKey;
    }
}
