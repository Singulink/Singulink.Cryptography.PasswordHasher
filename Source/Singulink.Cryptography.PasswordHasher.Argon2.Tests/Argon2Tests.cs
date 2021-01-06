using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Singulink.Cryptography.Tests
{
    [TestClass]
    public class Argon2Tests
    {
        private const string Password = "aIE*& YSfE#ZF';l<K";

        [TestMethod]
        public void Hash()
        {
            var hasher = new PasswordHasher(new Argon2HashAlgorithm(Argon2Type.Argon2id, 4, 512), 2) { Normalize = false };
            string hash = hasher.Hash(Password);

            Assert.IsTrue(hasher.Verify(hash, Password));
            Assert.IsTrue(hash.StartsWith("Argon2id128-4P-512MB", StringComparison.Ordinal));
        }
    }
}
