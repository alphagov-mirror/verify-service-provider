package uk.gov.ida.verifyserviceprovider.exceptions;

public class MissingUnsignedAssertionsHandlerException extends RuntimeException {
    public MissingUnsignedAssertionsHandlerException() {
        super("UnsignedAssertionsHandler missing: UnsignedAssertinosHandler can not be null in eIDAS enabled VSP");
    }
}
