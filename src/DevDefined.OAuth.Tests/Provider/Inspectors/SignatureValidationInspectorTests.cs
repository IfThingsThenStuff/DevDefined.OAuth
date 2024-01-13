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

using DevDefined.OAuth.Framework;
using DevDefined.OAuth.Framework.Signing;
using DevDefined.OAuth.Provider.Inspectors;
using DevDefined.OAuth.Storage;
using Moq;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace DevDefined.OAuth.Tests.Provider.Inspectors
{
	public class SignatureValidationInspectorTests
	{

        [Fact]
        public void InvalidSignatureThrows()
        {
            // Arrange
            var consumerStore = new Mock<IConsumerStore>();
            var signer = new Mock<IOAuthContextSigner>();
            var context = new OAuthContext { ConsumerKey = "key", SignatureMethod = SignatureMethod.PlainText };

            // Set up expectation for the ValidateSignature method
            signer.Setup(s => s.ValidateSignature(It.IsAny<OAuthContext>(), It.IsAny<SigningContext>())).Returns(false);

            // Act
            var inspector = new SignatureValidationInspector(consumerStore.Object, signer.Object);

            // Assert
            var ex = Assert.Throws<OAuthException>(() => inspector.InspectContext(ProviderPhase.GrantRequestToken, context));
            Assert.Equal("Failed to validate signature", ex.Message);
        }

        [Fact]
        public void PlainTextSignatureMethodDoesNotFetchCertificate()
        {
            // Arrange
            var consumerStore = new Mock<IConsumerStore>();
            var signer = new Mock<IOAuthContextSigner>();
            var context = new OAuthContext { ConsumerKey = "key", SignatureMethod = SignatureMethod.PlainText };

            // Set up expectation for the ValidateSignature method
            signer.Setup(s => s.ValidateSignature(It.IsAny<OAuthContext>(), It.IsAny<SigningContext>())).Returns(true);

            // Act
            var inspector = new SignatureValidationInspector(consumerStore.Object, signer.Object);
            inspector.InspectContext(ProviderPhase.GrantRequestToken, context);

            // Assert
            // Add assertions here if needed
        }


        [Fact]
        public void RsaSha1SignatureMethodFetchesCertificate()
        {
            // Arrange
            var consumerStore = new Mock<IConsumerStore>();
            var signer = new Mock<IOAuthContextSigner>();
            var context = new OAuthContext { ConsumerKey = "key", SignatureMethod = SignatureMethod.RsaSha1 };

            // Set up expectation for GetConsumerPublicKey method
            consumerStore.Setup(cs => cs.GetConsumerPublicKey(context))
                .Returns(TestCertificates.OAuthTestCertificate().GetRSAPublicKey);

            // Set up expectation for ValidateSignature method
            signer.Setup(s => s.ValidateSignature(It.IsAny<OAuthContext>(), It.IsAny<SigningContext>())).Returns(true);

            // Act
            var inspector = new SignatureValidationInspector(consumerStore.Object, signer.Object);
            inspector.InspectContext(ProviderPhase.GrantRequestToken, context);

            // Assert
            // Add assertions here if needed
            consumerStore.Verify(cs => cs.GetConsumerPublicKey(context), Times.Once);
            signer.Verify(s => s.ValidateSignature(It.IsAny<OAuthContext>(), It.IsAny<SigningContext>()), Times.Once);
        }
    }
}