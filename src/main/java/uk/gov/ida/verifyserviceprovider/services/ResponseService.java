package uk.gov.ida.verifyserviceprovider.services;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.validation.SamlResponseValidationException;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.security.AssertionDecrypter;
import uk.gov.ida.saml.security.EidasValidatorFactory;
import uk.gov.ida.saml.security.validators.ValidatedResponse;
import uk.gov.ida.saml.security.validators.signature.SamlResponseSignatureValidator;
import uk.gov.ida.verifyserviceprovider.dto.LevelOfAssurance;
import uk.gov.ida.verifyserviceprovider.dto.TranslatedResponseBody;
import uk.gov.ida.verifyserviceprovider.validators.InstantValidator;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class ResponseService {

    private final StringToOpenSamlObjectTransformer<Response> samlObjectTransformer;
    private final AssertionDecrypter assertionDecrypter;
    private final AssertionTranslator assertionTranslator;
    private final SamlResponseSignatureValidator responseSignatureValidator;
    private final InstantValidator instantValidator;
    private final ResponderCodeTranslator responderCodeTranslator;
    private final String hubEntityId;
    private final Optional<EidasValidatorFactory> eidasValidatorFactory;
    private final Optional<UnsignedAssertionsResponseHandler> unsignedAssertionsResponseHandler;

    public ResponseService(
            StringToOpenSamlObjectTransformer<Response> samlObjectTransformer,
            AssertionDecrypter assertionDecrypter,
            AssertionTranslator assertionTranslator,
            SamlResponseSignatureValidator responseSignatureValidator,
            InstantValidator instantValidator,
            ResponderCodeTranslator responderCodeTranslator,
            String hubEntityId,
            Optional<EidasValidatorFactory> eidasValidatorFactory,
            Optional<UnsignedAssertionsResponseHandler> unsignedAssertionsResponseHandler
    ) {
        this.samlObjectTransformer = samlObjectTransformer;
        this.assertionDecrypter = assertionDecrypter;
        this.assertionTranslator = assertionTranslator;
        this.responseSignatureValidator = responseSignatureValidator;
        this.instantValidator = instantValidator;
        this.responderCodeTranslator = responderCodeTranslator;
        this.hubEntityId = hubEntityId;
        this.eidasValidatorFactory = eidasValidatorFactory;
        this.unsignedAssertionsResponseHandler = unsignedAssertionsResponseHandler;
    }

    public TranslatedResponseBody convertTranslatedResponseBody(
        String decodedSamlResponse,
        String expectedInResponseTo,
        LevelOfAssurance expectedLevelOfAssurance,
        String entityId
    ) {
        Response response = samlObjectTransformer.apply(decodedSamlResponse);
        ValidatedResponse validatedResponse = getValidatedResponse(response);

        if (!expectedInResponseTo.equals(validatedResponse.getInResponseTo())) {
            throw new SamlResponseValidationException(
                String.format("Expected InResponseTo to be %s, but was %s", expectedInResponseTo, response.getInResponseTo())
            );
        }

        instantValidator.validate(validatedResponse.getIssueInstant(), "Response IssueInstant");

        StatusCode statusCode = validatedResponse.getStatus().getStatusCode();

        switch (statusCode.getValue()) {
            case StatusCode.RESPONDER:
                return responderCodeTranslator.translateResponderCode(statusCode);
            case StatusCode.SUCCESS:
                List<Assertion> assertions = assertionDecrypter.decryptAssertions(validatedResponse);
                if (assertionsContainEidasUnsignedAssertionsResponse(assertions)) {
                    UnsignedAssertionsResponseHandler handler = unsignedAssertionsResponseHandler.get();

                    ValidatedResponse validatedCountryResponse = handler.getValidatedResponse(assertions.get(0), expectedInResponseTo);
                    assertions = handler.decryptedAssertions(validatedCountryResponse, assertions.get(0));
                }
                return assertionTranslator.translateSuccessResponse(assertions, expectedInResponseTo, expectedLevelOfAssurance, entityId);
            default:
                throw new SamlResponseValidationException(String.format("Unknown SAML status: %s", statusCode.getValue()));
        }
    }

    private ValidatedResponse getValidatedResponse (Response response) {
        String issuer = response.getIssuer().getValue();
        return eidasValidatorFactory.isPresent() && !issuer.equals(hubEntityId) ?
                eidasValidatorFactory.get().getValidatedResponse(response) :
                responseSignatureValidator.validate(response, SPSSODescriptor.DEFAULT_ELEMENT_NAME);
    }

    private boolean assertionsContainEidasUnsignedAssertionsResponse(List<Assertion> assertions) {
        List<String> attributeNames = new ArrayList();
        assertions.stream().findFirst().get()
                .getAttributeStatements()
                .stream().findFirst().get()
                .getAttributes()
                .stream()
                .forEach(
                        attribute -> attributeNames.add(attribute.getName())
                );

        return attributeNames
                .stream()
                .anyMatch(
                        name -> name.equals(IdaConstants.Eidas_Attributes.UnsignedAssertions.EidasSamlResponse.NAME)
                );
    }
}
