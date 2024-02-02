using System;
using Xunit;

namespace DevDefined.OAuth.Tests.Utility
{
    public static class AssertionExtensions
    {
        public static void DoesNotThrow(Action value)
        {
            var ex = Record.Exception(value);
            Assert.Null(ex);
        }
    }
}
