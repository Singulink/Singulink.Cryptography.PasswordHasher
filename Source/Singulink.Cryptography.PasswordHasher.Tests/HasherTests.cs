using System;
using System.Runtime.InteropServices;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Singulink.Cryptography.Tests
{
    [TestClass]
    public class HasherTests
    {
        [TestMethod]
        public void DisallowSHA1()
        {
#pragma warning disable CS0618 // Type or member is obsolete
            Assert.ThrowsException<ArgumentException>(() => new PasswordHasher(PasswordHashAlgorithm.SHA1, 1));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        [TestMethod]
        public void UpgradeHashChain()
        {
            const string password = "wi4efunes4vq324rf";

            var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 1000);

            string sha256Hash1000Iterations = hasher.Hash(password);
            Assert.IsNull(hasher.UpgradeHashChain(sha256Hash1000Iterations));
            Assert.IsFalse(hasher.RequiresHashChainUpgrade(sha256Hash1000Iterations));
            Assert.IsFalse(hasher.RequiresRehash(sha256Hash1000Iterations));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Iterations, password));

            hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 3000);
            Assert.IsTrue(hasher.RequiresHashChainUpgrade(sha256Hash1000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Iterations));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Iterations, password));

            string sha256Hash1000Then2000Iterations = hasher.UpgradeHashChain(sha256Hash1000Iterations)!;
            Assert.IsNotNull(sha256Hash1000Then2000Iterations);
            Assert.IsNull(hasher.UpgradeHashChain(sha256Hash1000Then2000Iterations));
            Assert.IsFalse(hasher.RequiresHashChainUpgrade(sha256Hash1000Then2000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Then2000Iterations));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Then2000Iterations, password));

            hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 8000);
            Assert.IsTrue(hasher.RequiresHashChainUpgrade(sha256Hash1000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Iterations));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Iterations, password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Then2000Iterations, password));

            string sha256Hash1000Then2000Then5000Iterations = hasher.UpgradeHashChain(sha256Hash1000Then2000Iterations)!;
            Assert.IsNotNull(sha256Hash1000Then2000Then5000Iterations);
            Assert.IsNull(hasher.UpgradeHashChain(sha256Hash1000Then2000Then5000Iterations));
            Assert.IsFalse(hasher.RequiresHashChainUpgrade(sha256Hash1000Then2000Then5000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Then2000Then5000Iterations));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Then2000Then5000Iterations, password));

            string sha256Hash1000Then7000Iterations = hasher.UpgradeHashChain(sha256Hash1000Iterations)!;
            Assert.IsNotNull(sha256Hash1000Then7000Iterations);
            Assert.IsNull(hasher.UpgradeHashChain(sha256Hash1000Then7000Iterations));
            Assert.IsFalse(hasher.RequiresHashChainUpgrade(sha256Hash1000Then7000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Then7000Iterations));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Then7000Iterations, password));

            hasher = new PasswordHasher(PasswordHashAlgorithm.SHA512, 1000, PasswordHashAlgorithm.SHA256);

            string sha512HashFromSha256Hash1000Iterations = hasher.UpgradeHashChain(sha256Hash1000Iterations)!;
            Assert.IsNotNull(sha512HashFromSha256Hash1000Iterations);
            Assert.IsNull(hasher.UpgradeHashChain(sha512HashFromSha256Hash1000Iterations));
            Assert.IsFalse(hasher.RequiresHashChainUpgrade(sha512HashFromSha256Hash1000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha512HashFromSha256Hash1000Iterations));
            Assert.IsTrue(hasher.Verify(sha512HashFromSha256Hash1000Iterations, password));

            string sha512HashFromsha256Hash1000Then7000Iterations = hasher.UpgradeHashChain(sha256Hash1000Then7000Iterations)!;
            Assert.IsNotNull(sha512HashFromsha256Hash1000Then7000Iterations);
            Assert.IsNull(hasher.UpgradeHashChain(sha512HashFromsha256Hash1000Then7000Iterations));
            Assert.IsFalse(hasher.RequiresHashChainUpgrade(sha512HashFromsha256Hash1000Then7000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha512HashFromsha256Hash1000Then7000Iterations));
            Assert.IsTrue(hasher.Verify(sha512HashFromsha256Hash1000Then7000Iterations, password));
        }

        [TestMethod]
        public void UnknownAlgorithm()
        {
            const string password = "wi4efunes4vq324rf";
            var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 1000);
            string hash = hasher.Hash(password);

            hasher = new PasswordHasher(PasswordHashAlgorithm.SHA384, 10);

            Assert.ThrowsException<FormatException>(() => hasher.RequiresHashChainUpgrade(hash));
            Assert.ThrowsException<FormatException>(() => hasher.UpgradeHashChain(hash));
            Assert.ThrowsException<FormatException>(() => hasher.RequiresRehash(hash));
            Assert.ThrowsException<FormatException>(() => hasher.Verify(hash, password));
        }
    }
}
