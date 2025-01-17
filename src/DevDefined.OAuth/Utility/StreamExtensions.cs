﻿#region License

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

using System.IO;
using System.Net;
using System.Net.Http;

namespace DevDefined.OAuth.Utility
{
	public static class StreamExtensions
	{
		public static string ReadToEnd(this Stream stream)
		{
			if (!stream.CanRead)
			{
				throw new EndOfStreamException("The stream cannot be read");
			}

			if (stream.CanSeek)
			{
				stream.Seek(0, 0);
			}

			var reader = new StreamReader(stream);
			return reader.ReadToEnd();
		}

		public static string ReadToEnd(this WebResponse response)
		{
			return response.GetResponseStream().ReadToEnd();
		}

        public static string ReadToEnd(this HttpResponseMessage response)
        {
            using (var streamReader = new StreamReader(response.Content.ReadAsStreamAsync().Result))
            {
                return streamReader.ReadToEndAsync().Result;
            }
        }
        
    }
}