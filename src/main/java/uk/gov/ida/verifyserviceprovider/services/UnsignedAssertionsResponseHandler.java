package uk.gov.ida.verifyserviceprovider.services;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.Response;
import uk.gov.ida.saml.core.extensions.eidas.CountrySamlResponse;
import uk.gov.ida.saml.core.extensions.eidas.EncryptedAssertionKeys;
import uk.gov.ida.saml.core.validation.SamlResponseValidationException;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.security.AssertionDecrypter;
import uk.gov.ida.saml.security.EidasValidatorFactory;
import uk.gov.ida.saml.security.IdaKeyStoreCredentialRetriever;
import uk.gov.ida.saml.security.SecretKeyDecryptorFactory;
import uk.gov.ida.saml.security.exception.SamlFailedToDecryptException;
import uk.gov.ida.saml.security.validators.ValidatedResponse;
import uk.gov.ida.verifyserviceprovider.validators.InstantValidator;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import static uk.gov.ida.saml.security.errors.SamlTransformationErrorFactory.unableToDecrypt;
import static uk.gov.ida.verifyserviceprovider.validators.EidasEncryptionAlgorithmValidator.anEidasEncryptionAlgorithmValidator;

public class UnsignedAssertionsResponseHandler {
    private final EidasValidatorFactory eidasValidatorFactory;
    private final StringToOpenSamlObjectTransformer<Response> stringToResponseTransformer;
    private final InstantValidator instantValidator;
    private final SecretKeyDecryptorFactory secretKeyDecryptorFactory;
    private final String KEY_DELIMITER_REGEX = "\\.";

    public UnsignedAssertionsResponseHandler (
            EidasValidatorFactory eidasValidatorFactory,
            StringToOpenSamlObjectTransformer<Response> stringToResponseTransformer,
            InstantValidator instantValidator,
            IdaKeyStoreCredentialRetriever idaKeyStoreCredentialRetriever
    ) {
        this.eidasValidatorFactory = eidasValidatorFactory;
        this.stringToResponseTransformer = stringToResponseTransformer;
        this.instantValidator = instantValidator;
        this.secretKeyDecryptorFactory = new SecretKeyDecryptorFactory(idaKeyStoreCredentialRetriever);
    }

    public ValidatedResponse getValidatedResponse(
            Assertion hubResponseAssertion,
            String expectedInResponseTo
    ) {
        ValidatedResponse validatedResponse = eidasValidatorFactory.getValidatedResponse(
                stringToResponseTransformer.apply(
                        getCountryResponseStringFromAssertion(hubResponseAssertion)
                )
        );

        if (!expectedInResponseTo.equals(validatedResponse.getInResponseTo())) {
            throw new SamlResponseValidationException(
                    String.format("Expected InResponseTo to be %s, but was %s", expectedInResponseTo, validatedResponse.getInResponseTo())
            );
        }

        instantValidator.validate(validatedResponse.getIssueInstant(), "Response IssueInstant");

        return validatedResponse;
    }

    public List<Assertion> decryptedAssertions(
            ValidatedResponse validatedResponse,
            Assertion hubResponseAssertion
    ) {
        List<String> keys = getEncryptedAssertionKeysFromAssertion(hubResponseAssertion);
        return getAssertionDecrypter(keys).decryptAssertions(validatedResponse);
    }

    private AssertionDecrypter getAssertionDecrypter(List<String> keys) {
        try {
            return new AssertionDecrypter(
                    anEidasEncryptionAlgorithmValidator(),
                    secretKeyDecryptorFactory.createDecrypter(keys.get(0))
            );
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            throw new SamlFailedToDecryptException(unableToDecrypt("Unable to create decrypter from encrypted key"), e);
        }
    }

    private String getCountryResponseStringFromAssertion(Assertion hubResponseAssertion) {
        List<Attribute> attributes = hubResponseAssertion.getAttributeStatements().get(0).getAttributes();
        CountrySamlResponse countrySamlResponse = (CountrySamlResponse) attributes.get(0).getAttributeValues().get(0);
        return countrySamlResponse.getValue();
    }

    private List<String> getEncryptedAssertionKeysFromAssertion(Assertion hubResponseAssertion) {
        List<Attribute> attributes = hubResponseAssertion.getAttributeStatements().get(0).getAttributes();
        EncryptedAssertionKeys encryptedAssertionKeys = (EncryptedAssertionKeys) attributes.get(1).getAttributeValues().get(0);
        return Arrays.asList(encryptedAssertionKeys.getValue().split(KEY_DELIMITER_REGEX));
    }
}
