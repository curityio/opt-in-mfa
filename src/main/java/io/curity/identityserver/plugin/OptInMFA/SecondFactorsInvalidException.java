package io.curity.identityserver.plugin.OptInMFA;

public class SecondFactorsInvalidException extends RuntimeException
{
    public SecondFactorsInvalidException()
    {
        super("There was a problem with the authentication. Please start the process again.");
    }
}
