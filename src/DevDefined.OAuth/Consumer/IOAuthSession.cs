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
using System.Collections;
using DevDefined.OAuth.Framework;

namespace DevDefined.OAuth.Consumer
{
	public interface IOAuthSession
	{
		IOAuthConsumerContext ConsumerContext { get; set; }
		Uri RequestTokenUri { get; set; }
		Uri AccessTokenUri { get; set; }
		Uri UserAuthorizeUri { get; set; }
		Uri ProxyServerUri { get; set; }
		Uri CallbackUri { get; set; }
		IToken AccessToken { get; set; }
		Action<string> ResponseBodyAction { get; set; }
		IConsumerRequest Request();
		IConsumerRequest Request(IToken accessToken);
		IToken GetRequestToken();
		IToken GetRequestToken(string method);
		IToken ExchangeRequestTokenForAccessToken(IToken requestToken);
		IToken ExchangeRequestTokenForAccessToken(IToken requestToken, string verificationCode);
		IToken ExchangeRequestTokenForAccessToken(IToken requestToken, string method, string verificationCode);
		IToken GetAccessTokenUsingXAuth(string authMode, string username, string password);
		IConsumerRequest BuildRequestTokenContext(string method);
		IConsumerRequest BuildExchangeRequestTokenForAccessTokenContext(IToken requestToken, string method, string verificationCode);
		IConsumerRequest BuildAccessTokenContext(string method, string xAuthMode, string xAuthUsername, string xAuthPassword);
		string GetUserAuthorizationUrlForToken(IToken token, string callbackUrl);
		string GetUserAuthorizationUrlForToken(IToken token);
		IOAuthSession WithFormParameters(IDictionary dictionary);
		IOAuthSession WithFormParameters(object anonymousClass);
		IOAuthSession WithQueryParameters(IDictionary dictionary);
		IOAuthSession WithQueryParameters(object anonymousClass);
		IOAuthSession WithCookies(IDictionary dictionary);
		IOAuthSession WithCookies(object anonymousClass);
		IOAuthSession WithHeaders(IDictionary dictionary);
		IOAuthSession WithHeaders(object anonymousClass);
		IOAuthSession RequiresCallbackConfirmation();
	}
}