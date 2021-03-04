package io.curity.identityserver.plugin.OptInMFA;

public class MissingStepException extends RuntimeException
{
    public MissingStepException()
    {
        super("There was a problem with the authentication. Please start the process again.");
    }
}
