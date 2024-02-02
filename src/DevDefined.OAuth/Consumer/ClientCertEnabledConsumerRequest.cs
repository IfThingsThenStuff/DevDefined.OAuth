#region License

// The MIT License
//
// Copyright (c) 2006-2008 DevDefined Limited.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#endregion

using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using DevDefined.OAuth.Framework;

namespace DevDefined.OAuth.Consumer
{
	public class ClientCertEnabledConsumerRequest : ConsumerRequest
	{
		readonly ICertificateFactory _certificateFactory;

		/// <summary>
		/// Initializes a new instance of the <see cref="ClientCertEnabledConsumerRequest"/> class.
		/// </summary>
		/// <param name="certificateFactory">The certificate factory.</param>
		/// <param name="context">The context.</param>
		/// <param name="consumerContext">The consumer context.</param>
		/// <param name="token">The token.</param>
		public ClientCertEnabledConsumerRequest(ICertificateFactory certificateFactory, IOAuthContext context, IOAuthConsumerContext consumerContext, IToken token)
			: base(context, consumerContext, token)
		{
			_certificateFactory = certificateFactory;
		}

        /// <summary>
        /// Converts the current ConsumerRequest to an HttpWebRequest
        /// </summary>
        /// <returns>Return an HttpRequestMessage with a client certificate attached.</returns>
        public override HttpRequestMessage ToWebRequest()
        {
            HttpRequestMessage webRequest = base.ToWebRequest();

            X509Certificate2 certificate = _certificateFactory.CreateCertificate();

            // Attach the certificate to the HttpRequestMessage
            if (certificate != null)
            {
                var handler = new HttpClientHandler();
                handler.ClientCertificates.Add(certificate);

                using (var httpClient = new HttpClient(handler))
                {
                    // Copy relevant properties from base request to the new HttpRequestMessage
                    webRequest.Headers.ToList().ForEach(header => httpClient.DefaultRequestHeaders.Add(header.Key, header.Value));
                    webRequest.Content?.Headers.ToList().ForEach(header => httpClient.DefaultRequestHeaders.Add(header.Key, header.Value));

                    // Perform the request to obtain any additional information
                    HttpResponseMessage response = httpClient.SendAsync(webRequest).Result;
                    response.EnsureSuccessStatusCode();

                    // You may need to process the response if needed
                    var responseBody = response.Content.ReadAsStringAsync().Result;
                    // Do something with responseBody

                    // Dispose of the HttpClient
                    httpClient.Dispose();
                }
            }

            return webRequest;
        }

    }
}