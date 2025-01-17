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

using System;
using System.Collections.Specialized;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Xml.Linq;
using DevDefined.OAuth.Framework;

namespace DevDefined.OAuth.Consumer
{
	public class ConsumerRequest : IConsumerRequest
	{
		readonly IOAuthConsumerContext _consumerContext;
		readonly IOAuthContext _context;
		readonly IToken _token;
		private readonly HttpClient _httpClient;

		public ConsumerRequest(IOAuthContext context, IOAuthConsumerContext consumerContext, IToken token)
		{
			if (context == null) throw new ArgumentNullException("context");
			if (consumerContext == null) throw new ArgumentNullException("consumerContext");
			_context = context;
			_consumerContext = consumerContext;
			_token = token;
			_httpClient = new HttpClient();
		}

		string ResponseBody { get; set; }

		public IOAuthConsumerContext ConsumerContext
		{
			get { return _consumerContext; }
		}

		public IOAuthContext Context
		{
			get { return _context; }
		}

		public XDocument ToDocument()
		{
			return XDocument.Parse(ToString());
		}

		public byte[] ToBytes()
		{
			return Convert.FromBase64String(ToString());
		}

		public RequestDescription GetRequestDescription()
		{
			if (string.IsNullOrEmpty(_context.Signature))
			{
				if (_token != null)
				{
					_consumerContext.SignContextWithToken(_context, _token);
				}
				else
				{
					_consumerContext.SignContext(_context);
				}
			}

			Uri uri = _context.GenerateUri();

			var description = new RequestDescription
			{
				Url = uri,
				Method = _context.RequestMethod,
			};

			if ((_context.FormEncodedParameters != null) && (_context.FormEncodedParameters.Count > 0))
			{
				description.ContentType = Parameters.HttpFormEncoded;
				description.Body = UriUtility.FormatQueryString(_context.FormEncodedParameters.ToQueryParametersExcludingTokenSecret());
			}
			else if (!string.IsNullOrEmpty(RequestBody))
			{
				description.Body = UriUtility.UrlEncode(RequestBody);
			}

			else if (_context.RawContent != null)
			{
				description.ContentType = _context.RawContentType;
				description.RawBody = _context.RawContent;
			}

			if (_context.Headers != null)
			{
				description.Headers.Add(_context.Headers);
			}

			if (_consumerContext.UseHeaderForOAuthParameters)
			{
				description.Headers[Parameters.OAuth_Authorization_Header] = _context.GenerateOAuthParametersForHeader();
			}

			return description;
		}

		public HttpResponseMessage ToWebResponse()
		{
			return ToWebResponseAsync().Result;
		}

		public async Task<HttpResponseMessage> ToWebResponseAsync()
		{
			try
			{
				HttpRequestMessage request = ToWebRequest();
				using (var httpClient = new HttpClient())
				{
					return await httpClient.SendAsync(request);
				}
			}
			catch (WebException httpEx)
			{
				OAuthException authException;

				if (WebExceptionHelper.TryWrapException(Context, httpEx, out authException, ResponseBodyAction))
				{
					throw authException;
				}

				throw;
			}
		}


		public NameValueCollection ToBodyParameters()
		{
			try
			{
				string encodedFormParameters = ToString();

				if (ResponseBodyAction != null)
				{
					ResponseBodyAction(encodedFormParameters);
				}

				try
				{
					return HttpUtility.ParseQueryString(encodedFormParameters);
				}
				catch (ArgumentNullException)
				{
					throw Error.FailedToParseResponse(encodedFormParameters);
				}
			}
			catch (WebException webEx)
			{
				throw Error.RequestFailed(webEx);
			}
		}

		public IConsumerRequest SignWithoutToken()
		{
			EnsureRequestHasNotBeenSignedYet();
			_consumerContext.SignContext(_context);
			return this;
		}

		public IConsumerRequest SignWithToken()
		{
			return SignWithToken(_token);
		}

		public IConsumerRequest SignWithToken(IToken token)
		{
			EnsureRequestHasNotBeenSignedYet();
			ConsumerContext.SignContextWithToken(_context, token);
			return this;
		}

		public Uri ProxyServerUri { get; set; }

		public Action<string> ResponseBodyAction { get; set; }

		public string AcceptsType { get; set; }

		/// <summary>
		/// Override the default request timeout in milliseconds.
		/// Sets the <see cref="System.Net.HttpWebRequest.Timeout"/> property.
		/// </summary>
		public int? Timeout { get; set; }

		public string RequestBody { get; set; }

		public virtual HttpRequestMessage ToWebRequest()
		{
			RequestDescription description = GetRequestDescription();

			using (var httpClient = GetHttpClient())
			{
				var request = new HttpRequestMessage
				{
					RequestUri = description.Url,
					Method = new HttpMethod(description.Method)
				};

				request.Headers.Add("User-Agent", _consumerContext.UserAgent);

				if (Timeout.HasValue)
				{
					_httpClient.Timeout = TimeSpan.FromMilliseconds(Timeout.Value);
				}

				if (!string.IsNullOrEmpty(AcceptsType))
				{
					request.Headers.Accept.ParseAdd(AcceptsType);
				}

				try
				{
					var modifiedDateString = Context.Headers.Get("If-Modified-Since");
					if (modifiedDateString != null)

					{
						request.Headers.IfModifiedSince = DateTimeOffset.Parse(modifiedDateString);
					}
				}
				catch (Exception ex)
				{
					throw new ApplicationException("If-Modified-Since header could not be parsed as a datetime", ex);
				}

				if (description.Headers.Count > 0)
				{
					foreach (var header in description.Headers.AllKeys)
					{
						request.Headers.Add(header, description.Headers[header]);
					}
				}

				if (!string.IsNullOrEmpty(description.Body))
				{
					request.Content = new StringContent(description.Body);
					request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(description.ContentType);
				}
				else if (description.RawBody != null && description.RawBody.Length > 0)
				{
					request.Content = new ByteArrayContent(description.RawBody);
					request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(description.ContentType);
				}

				return request;
			}


		}

		private HttpClient GetHttpClient()
		{
			var handler = GetHttpClientHandler();
			return new HttpClient(GetHttpClientHandler());
		}

		private HttpClientHandler GetHttpClientHandler()
		{
			var handler = new HttpClientHandler();

			if (ProxyServerUri != null)
			{
				handler.Proxy = new WebProxy(ProxyServerUri, false);
			}

			return handler;
		}

		public override string ToString()
		{
			if (string.IsNullOrEmpty(ResponseBody))
			{
				using (var response = ToWebResponse())
				{
					using (var streamReader = new StreamReader(response.Content.ReadAsStreamAsync().Result))
					{
						ResponseBody = streamReader.ReadToEndAsync().Result;
					}
				}
			}

			return ResponseBody;
		}

		void EnsureRequestHasNotBeenSignedYet()
		{
			if (!string.IsNullOrEmpty(_context.Signature))
			{
				throw Error.ThisConsumerRequestHasAlreadyBeenSigned();
			}
		}
	}
}
