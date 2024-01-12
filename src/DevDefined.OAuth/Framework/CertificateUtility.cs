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
        //public static X509Certificate2 LoadCertificateFromStrings(string privateKey, string certificate)
        //{
        //	var parser = new AsnKeyParser(Convert.FromBase64String(privateKey));
        //	RSAParameters parameters = parser.ParseRSAPrivateKey();
        //	var x509 = new X509Certificate2(Encoding.ASCII.GetBytes(certificate));
        //	var provider = new RSACryptoServiceProvider();
        //	provider.ImportParameters(parameters);
        //	x509.PrivateKey = provider;

        //	return x509;
        //}

        // Assuming the following method for loading the certificate from strings
        public static X509Certificate2 LoadCertificateFromStrings(string privateKey, string certificate)
        {
            byte[] privateKeyBytes = Encoding.UTF8.GetBytes(privateKey);
            byte[] certificateBytes = Encoding.UTF8.GetBytes(certificate);

            X509Certificate2 cert = new X509Certificate2(certificateBytes, (string)null, X509KeyStorageFlags.Exportable);

            if (privateKeyBytes != null && privateKeyBytes.Length > 0)
            {
                using (RSA rsa = RSA.Create())
                {
                    rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

                    RSA rsaWithPrivateKey = cert.GetRSAPrivateKey() ?? rsa;

                    RSA rsaPrivateKey = RSA.Create();
                    rsaPrivateKey.ImportParameters(rsaWithPrivateKey.ExportParameters(true));

                    X509Certificate2 certWithPrivateKey = cert.CopyWithPrivateKey(rsaPrivateKey);

                    // Optional: If you want to export it for use in other scenarios
                    byte[] exportedCertWithPrivateKey = certWithPrivateKey.Export(X509ContentType.Pkcs12, (string)null);
                    return new X509Certificate2(exportedCertWithPrivateKey, (string)null, X509KeyStorageFlags.MachineKeySet);
                }
            }

            return cert;
        }

    }
}