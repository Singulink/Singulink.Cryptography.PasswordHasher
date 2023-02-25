using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Singulink.Cryptography.Tests;

[TestClass]
public class NormalizerTests
{
    private const string Password = "wi4efu\x00A0nes4vq324rf"; // contains an alternate space that will normalize
    private const string PasswordWithNormalSpace = "wi4efu nes4vq324rf";

    [TestMethod]
    public void NormalizeSpaces()
    {
        string normalized = PasswordNormalizer.Normalize(Password);

        Assert.AreNotEqual(Password, normalized);
        Assert.AreEqual(normalized, PasswordWithNormalSpace);
    }
}