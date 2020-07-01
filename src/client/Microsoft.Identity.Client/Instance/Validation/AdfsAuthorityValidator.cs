// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Identity.Client.Internal;
using Microsoft.Identity.Client.OAuth2;

namespace Microsoft.Identity.Client.Instance.Validation
{
    internal class AdfsAuthorityValidator : IAuthorityValidator
    {
        private readonly IServiceBundle _serviceBundle;

        public AdfsAuthorityValidator(IServiceBundle serviceBundle)
        {
            _serviceBundle = serviceBundle;
        }

        public async Task ValidateAuthorityAsync(
            AuthorityInfo authorityInfo,
            RequestContext requestContext,
            string userPrincipalName)
        {
            if (authorityInfo.ValidateAuthority)
            {

                DrsMetadataResponse drsResponse = await GetMetadataFromEnrollmentServerAsync(userPrincipalName, requestContext)
                                      .ConfigureAwait(false);

                if (drsResponse.IdentityProviderService?.PassiveAuthEndpoint == null)
                {
                    throw new MsalServiceException(
                        MsalError.MissingPassiveAuthEndpoint,
                        MsalErrorMessage.CannotFindTheAuthEndpont);
                }

                string resource = string.Format(CultureInfo.InvariantCulture, "https://{0}", authorityInfo.Host);
                string webFingerUrl = Constants.FormatAdfsWebFingerUrl(
                    drsResponse.IdentityProviderService.PassiveAuthEndpoint.Host,
                    resource);


                Http.HttpResponse httpResponse = await _serviceBundle.HttpManager.SendGetAsync(new Uri(webFingerUrl), null, requestContext.Logger)
                                                       .ConfigureAwait(false);

                if (httpResponse.StatusCode != HttpStatusCode.OK)
                {
                    throw MsalServiceExceptionFactory.FromHttpResponse(
                        MsalError.InvalidAuthority,
                        MsalErrorMessage.AuthorityValidationFailed,
                        httpResponse);
                }

                var wfr = OAuth2Client.CreateResponse<AdfsWebFingerResponse>(httpResponse, requestContext, false);
                if (wfr.Links.FirstOrDefault(
                        a => a.Rel.Equals(Constants.DefaultRealm, StringComparison.OrdinalIgnoreCase) &&
                             a.Href.Equals(resource, StringComparison.OrdinalIgnoreCase)) == null)
                {
                    throw new MsalClientException(
                        MsalError.InvalidAuthority,
                        MsalErrorMessage.InvalidAuthorityOpenId);
                }
            }
        }

        private async Task<DrsMetadataResponse> GetMetadataFromEnrollmentServerAsync(
            string userPrincipalName,
            RequestContext requestContext)
        {
            try
            {
                // attempt to connect to on-premise enrollment server first.
                return await QueryEnrollmentServerEndpointAsync(
                   Constants.FormatEnterpriseRegistrationOnPremiseUri(AdfsUpnHelper.GetDomainFromUpn(userPrincipalName)),
                   requestContext).ConfigureAwait(false);
            }
            catch (Exception exc)
            {
                requestContext.Logger.InfoPiiWithPrefix(
                    exc,
                    "On-Premise ADFS enrollment server endpoint lookup failed. Error - ");
            }

            return await QueryEnrollmentServerEndpointAsync(
               Constants.FormatEnterpriseRegistrationInternetUri(AdfsUpnHelper.GetDomainFromUpn(userPrincipalName)),
               requestContext).ConfigureAwait(false);
        }

        private async Task<DrsMetadataResponse> QueryEnrollmentServerEndpointAsync(string endpoint, RequestContext requestContext)
        {
            var client = new OAuth2Client(requestContext.Logger, _serviceBundle.HttpManager, _serviceBundle.MatsTelemetryManager);
            client.AddQueryParameter("api-version", "1.0");
            return await client.ExecuteRequestAsync<DrsMetadataResponse>(new Uri(endpoint), HttpMethod.Get, requestContext)
                               .ConfigureAwait(false);
        }
    }
}
