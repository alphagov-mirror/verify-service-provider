package uk.gov.ida.verifyserviceprovider.resources;

import uk.gov.ida.verifyserviceprovider.VerifyServiceProviderConfiguration;
import uk.gov.ida.verifyserviceprovider.dto.RequestGenerationBody;
import uk.gov.ida.verifyserviceprovider.dto.RequestResponseBody;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;

@Path("/generate-request")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class GenerateAuthnRequestResource {

    VerifyServiceProviderConfiguration configuration;

    public GenerateAuthnRequestResource(VerifyServiceProviderConfiguration configuration) {
        this.configuration = configuration;
    }

    @POST
    public Response generateAuthnRequest(RequestGenerationBody requestGenerationBody) {
        String samlRequest = "some-saml";
        String secureToken = "some-secure-token";
        URI location = URI.create("http://example.com");
        return Response.ok(new RequestResponseBody(samlRequest, secureToken, location)).build();
    }
}
