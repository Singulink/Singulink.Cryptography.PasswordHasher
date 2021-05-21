using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Singulink.Cryptography.Tests
{
    [TestClass]
    public class HasherTests
    {
        private const string Password = "wi4efu\x00A0nes4vq324rf"; // contains an alternate space that will normalize
        private const string PasswordWithNormalSpace = "wi4efu nes4vq324rf";
        private const string PasswordWithIllegalChars = "f3l43foj\nk*#lKSEF";
        private const string NotThePassword = "12345";

        [DataTestMethod]
        [DataRow(false, false)]
        [DataRow(false, true)]
        [DataRow(true, false)]
        [DataRow(true, true)]
        public void UpdateHashChain(bool normalize, bool encrypt)
        {
            var options = new PasswordHasherOptions {
                EncryptionParameters = encrypt ? new(123, HashEncryptionAlgorithm.AES128, new byte[] { 43, 12, 64, 63, 1, 6, 74, 123, 4, 15, 11, 84, 26, 125, 11, 6 }) : null,
                Normalize = normalize,
            };

            int extraHashSections = 0;

            if (normalize)
                extraHashSections++;

            if (encrypt)
                extraHashSections++;

            var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 1000, options);

            string sha256Hash1000Iterations = hasher.Hash(Password);
            Assert.AreEqual(2 + extraHashSections, sha256Hash1000Iterations.Split(' ').Length);

            Assert.IsNull(hasher.Update(sha256Hash1000Iterations));
            Assert.IsFalse(hasher.RequiresUpdate(sha256Hash1000Iterations));
            Assert.IsFalse(hasher.RequiresRehash(sha256Hash1000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Iterations, Password));
            Assert.IsFalse(hasher.Verify(sha256Hash1000Iterations, NotThePassword));

            hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 3000, options);

            Assert.IsTrue(hasher.RequiresUpdate(sha256Hash1000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Iterations, Password));
            Assert.IsFalse(hasher.Verify(sha256Hash1000Iterations, NotThePassword));

            string sha256Hash1000Then2000Iterations = hasher.Update(sha256Hash1000Iterations)!;
            Assert.IsNotNull(sha256Hash1000Then2000Iterations);
            Assert.AreEqual(3 + extraHashSections, sha256Hash1000Then2000Iterations.Split(' ').Length);

            Assert.IsNull(hasher.Update(sha256Hash1000Then2000Iterations));
            Assert.IsFalse(hasher.RequiresUpdate(sha256Hash1000Then2000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Then2000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Then2000Iterations, Password));
            Assert.IsFalse(hasher.Verify(sha256Hash1000Then2000Iterations, NotThePassword));

            hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 8000, options);
            Assert.IsTrue(hasher.RequiresUpdate(sha256Hash1000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Then2000Iterations, Password));
            Assert.IsFalse(hasher.Verify(sha256Hash1000Then2000Iterations, NotThePassword));

            string sha256Hash1000Then2000Then5000Iterations = hasher.Update(sha256Hash1000Then2000Iterations)!;
            Assert.IsNotNull(sha256Hash1000Then2000Then5000Iterations);
            Assert.AreEqual(4 + extraHashSections, sha256Hash1000Then2000Then5000Iterations.Split(' ').Length);

            Assert.IsNull(hasher.Update(sha256Hash1000Then2000Then5000Iterations));
            Assert.IsFalse(hasher.RequiresUpdate(sha256Hash1000Then2000Then5000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Then2000Then5000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Then2000Then5000Iterations, Password));
            Assert.IsFalse(hasher.Verify(sha256Hash1000Then2000Then5000Iterations, NotThePassword));

            string sha256Hash1000Then7000Iterations = hasher.Update(sha256Hash1000Iterations)!;
            Assert.IsNotNull(sha256Hash1000Then7000Iterations);
            Assert.AreEqual(3 + extraHashSections, sha256Hash1000Then7000Iterations.Split(' ').Length);

            Assert.IsNull(hasher.Update(sha256Hash1000Then7000Iterations));
            Assert.IsFalse(hasher.RequiresUpdate(sha256Hash1000Then7000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Then7000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Then7000Iterations, Password));
            Assert.IsFalse(hasher.Verify(sha256Hash1000Then7000Iterations, NotThePassword));

            options.LegacyHashAlgorithms.Add(PasswordHashAlgorithm.SHA256);
            hasher = new PasswordHasher(PasswordHashAlgorithm.SHA512, 1000, options);

            string sha512HashFromSha256Hash1000Iterations = hasher.Update(sha256Hash1000Iterations)!;
            Assert.IsNotNull(sha512HashFromSha256Hash1000Iterations);
            Assert.AreEqual(3 + extraHashSections, sha512HashFromSha256Hash1000Iterations.Split(' ').Length);

            Assert.IsNull(hasher.Update(sha512HashFromSha256Hash1000Iterations));
            Assert.IsFalse(hasher.RequiresUpdate(sha512HashFromSha256Hash1000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha512HashFromSha256Hash1000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha512HashFromSha256Hash1000Iterations, Password));
            Assert.IsFalse(hasher.Verify(sha512HashFromSha256Hash1000Iterations, NotThePassword));

            string sha512HashFromsha256Hash1000Then7000Iterations = hasher.Update(sha256Hash1000Then7000Iterations)!;
            Assert.IsNotNull(sha512HashFromsha256Hash1000Then7000Iterations);
            Assert.AreEqual(4 + extraHashSections, sha512HashFromsha256Hash1000Then7000Iterations.Split(' ').Length);

            Assert.IsNull(hasher.Update(sha512HashFromsha256Hash1000Then7000Iterations));
            Assert.IsFalse(hasher.RequiresUpdate(sha512HashFromsha256Hash1000Then7000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha512HashFromsha256Hash1000Then7000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha512HashFromsha256Hash1000Then7000Iterations, Password));
            Assert.IsFalse(hasher.Verify(sha512HashFromsha256Hash1000Then7000Iterations, NotThePassword));
        }

        [TestMethod]
        public void UpdateMasterKey()
        {
            HashEncryptionParameters encryption1 = new(123, HashEncryptionAlgorithm.AES128, new byte[] { 43, 12, 64, 63, 1, 6, 74, 123, 4, 15, 11, 84, 26, 125, 11, 6 });
            HashEncryptionParameters encryption2 = new(456, HashEncryptionAlgorithm.AES128, new byte[] { 44, 12, 64, 63, 1, 6, 74, 123, 4, 15, 11, 84, 26, 125, 11, 6 });

            var options1 = new PasswordHasherOptions {
                EncryptionParameters = encryption1,
            };

            var options2_0 = new PasswordHasherOptions {
                EncryptionParameters = encryption2,
            };

            var options2_1 = new PasswordHasherOptions {
                EncryptionParameters = encryption2,
                LegacyEncryptionParameters = { encryption1 },
            };

            var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA512, 1000);

            string hash = hasher.Hash(Password);
            Assert.IsTrue(hasher.Verify(hash, Password));
            Assert.IsFalse(hasher.Verify(hash, NotThePassword));

            var hasher1 = new PasswordHasher(PasswordHashAlgorithm.SHA512, 1000, options1);
            Assert.IsTrue(hasher1.RequiresUpdate(hash));

            string hash1 = hasher1.Update(hash)!;
            Assert.AreNotEqual(hash1, hash);

            Assert.IsTrue(hasher1.Verify(hash1, Password));
            Assert.IsFalse(hasher1.Verify(hash1, NotThePassword));
            Assert.ThrowsException<FormatException>(() => hasher.Verify(hash1, Password));

            var hasher2_0 = new PasswordHasher(PasswordHashAlgorithm.SHA512, 1000, options2_0);
            Assert.IsTrue(hasher2_0.RequiresUpdate(hash));
            Assert.ThrowsException<FormatException>(() => hasher2_0.RequiresUpdate(hash1));

            string hash2_0 = hasher2_0.Update(hash)!;
            Assert.IsTrue(hasher2_0.Verify(hash2_0, Password));
            Assert.IsFalse(hasher2_0.Verify(hash2_0, NotThePassword));
            Assert.ThrowsException<FormatException>(() => hasher2_0.Update(hash1));

            var hasher2_1 = new PasswordHasher(PasswordHashAlgorithm.SHA512, 1000, options2_1);
            Assert.IsTrue(hasher2_1.RequiresUpdate(hash));
            Assert.IsTrue(hasher2_1.RequiresUpdate(hash1));

            string hash2_1 = hasher2_1.Update(hash1)!;
            Assert.AreNotEqual(hash2_1, hash2_0); // AES IV values should be different for each encryption
            Assert.AreNotEqual(hash2_1, hash1);

            Assert.IsTrue(hasher2_1.Verify(hash, Password));
            Assert.IsTrue(hasher2_1.Verify(hash1, Password));
            Assert.IsTrue(hasher2_1.Verify(hash2_1, Password));

            Assert.IsFalse(hasher2_1.Verify(hash, NotThePassword));
            Assert.IsFalse(hasher2_1.Verify(hash1, NotThePassword));
            Assert.IsFalse(hasher2_1.Verify(hash2_1, NotThePassword));
        }

        [TestMethod]
        public void Normalization()
        {
            PasswordHasherOptions options = new() { Normalize = false };
            PasswordHasher hasher = new(PasswordHashAlgorithm.SHA384, 100, options);

            string hash = hasher.Hash(Password);
            Assert.IsFalse(hasher.RequiresUpdate(hash));
            Assert.IsFalse(hasher.RequiresRehash(hash, Password));
            Assert.IsTrue(hasher.Verify(hash, Password));
            Assert.IsFalse(hasher.Verify(hash, PasswordWithNormalSpace));

            options.Normalize = true;
            hasher = new(PasswordHashAlgorithm.SHA384, 100, options);
            Assert.IsFalse(hasher.RequiresUpdate(hash));
            Assert.IsTrue(hasher.RequiresRehash(hash, Password));

            hash = hasher.Hash(Password);
            Assert.IsTrue(hasher.Verify(hash, Password));
            Assert.IsTrue(hasher.Verify(hash, PasswordWithNormalSpace));
            Assert.IsFalse(hasher.Verify(hash, NotThePassword));
        }

        [TestMethod]
        public void RehashWithIllegalChars()
        {
            PasswordHasherOptions options = new() { Normalize = false };
            PasswordHasher hasher = new(PasswordHashAlgorithm.SHA256, 200, options);
            string hash = hasher.Hash(PasswordWithIllegalChars);
            Assert.IsFalse(hash.StartsWith("!", StringComparison.Ordinal));
            Assert.IsTrue(hasher.Verify(hash, PasswordWithIllegalChars));
            Assert.IsFalse(hasher.Verify(hash, Password));
            Assert.IsFalse(hasher.RequiresRehash(hash, PasswordWithIllegalChars));

            options.Normalize = true;
            hasher = new(PasswordHashAlgorithm.SHA256, 200, options);
            Assert.IsFalse(hasher.RequiresRehash(hash, PasswordWithIllegalChars));

            hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 400);
            Assert.IsTrue(hasher.RequiresRehash(hash, PasswordWithIllegalChars));

            hash = hasher.Rehash(PasswordWithIllegalChars);
            Assert.IsFalse(hash.StartsWith("!", StringComparison.Ordinal));
            Assert.IsTrue(hasher.Verify(hash, PasswordWithIllegalChars));
            Assert.IsFalse(hasher.Verify(hash, Password));
        }

        [TestMethod]
        public void RehashWithLegalChars()
        {
            PasswordHasherOptions options = new() { Normalize = false };
            PasswordHasher hasher = new(PasswordHashAlgorithm.SHA256, 200, options);
            string hash = hasher.Hash(Password);
            Assert.IsFalse(hash.StartsWith("!", StringComparison.Ordinal));
            Assert.IsTrue(hasher.Verify(hash, Password));

            options.Normalize = true;
            hasher = new(PasswordHashAlgorithm.SHA256, 200, options);
            Assert.IsTrue(hasher.RequiresRehash(hash, Password));

            hash = hasher.Rehash(Password);
            Assert.IsTrue(hash.StartsWith("!", StringComparison.Ordinal));
            Assert.IsFalse(hasher.RequiresRehash(hash, Password));
            Assert.IsTrue(hasher.Verify(hash, Password));
            Assert.IsFalse(hasher.Verify(hash, PasswordWithIllegalChars));
        }

        [TestMethod]
        public void DisallowSHA1()
        {
            #pragma warning disable CS0618 // Type or member is obsolete
            Assert.ThrowsException<ArgumentException>(() => new PasswordHasher(PasswordHashAlgorithm.SHA1, 1));
            #pragma warning restore CS0618 // Type or member is obsolete
        }

        [TestMethod]
        public void UnknownAlgorithm()
        {
            var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 1000);
            string hash = hasher.Hash(Password);

            hasher = new PasswordHasher(PasswordHashAlgorithm.SHA384, 10);

            Assert.ThrowsException<FormatException>(() => hasher.RequiresUpdate(hash));
            Assert.ThrowsException<FormatException>(() => hasher.Update(hash));
            Assert.ThrowsException<FormatException>(() => hasher.RequiresRehash(hash, Password));
            Assert.ThrowsException<FormatException>(() => hasher.Verify(hash, Password));
        }
    }
}
