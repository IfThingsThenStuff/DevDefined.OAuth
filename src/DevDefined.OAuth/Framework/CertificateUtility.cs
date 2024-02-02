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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DevDefined.OAuth.KeyInterop;

namespace DevDefined.OAuth.Framework
{
	public static class CertificateUtility
	{
        /// <summary>
        /// Loads a certificate given both it's private and public keys - generally used to 
        /// load keys provided on the OAuth wiki's for verification of implementation correctness.
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="certificate"></param>
        /// <returns></returns>
        public static X509Certificate2 LoadCertificateFromStrings(string privateKey, string certificate)
        {
            byte[] privateKeyBytes = Convert.FromBase64String(privateKey);
            RSAParameters parameters = ParseRSAPrivateKey(privateKeyBytes);

            X509Certificate2 x509Certificate = new X509Certificate2(Encoding.ASCII.GetBytes(certificate));

            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(parameters);
                RSA privateKeyRsa = x509Certificate.GetRSAPrivateKey() ?? rsa;

                X509Certificate2 certificateWithPrivateKey = x509Certificate.CopyWithPrivateKey(privateKeyRsa);

                // Optional: If you want to export it for use in other scenarios
                byte[] exportedCertWithPrivateKey = certificateWithPrivateKey.Export(X509ContentType.Pkcs12, (string)null);

                return new X509Certificate2(exportedCertWithPrivateKey, (string)null, X509KeyStorageFlags.MachineKeySet);
            }
        }

        private static RSAParameters ParseRSAPrivateKey(byte[] privateKeyBytes)
        {
            // Implement the parsing logic for the RSA private key here
            // This is a basic example, and you may need to adjust it based on the actual format of your private key

            // Assuming DER encoding (ASN.1 format)
            // Note: This is a basic example, and may need adjustments based on the actual private key format

            var keyParser = new AsnKeyParser(privateKeyBytes);
            return keyParser.ParseRSAPrivateKey();
        }
    }
}