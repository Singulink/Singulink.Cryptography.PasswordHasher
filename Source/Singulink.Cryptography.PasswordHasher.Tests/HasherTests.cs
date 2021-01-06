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

        [DataTestMethod]
        [DataRow(false, false)]
        [DataRow(false, true)]
        [DataRow(true, false)]
        [DataRow(true, true)]
        public void UpdateHashChain(bool normalize, bool encrypt)
        {
            byte[] key = new byte[] { 43, 12, 64, 63, 1, 6, 74, 123, 4, 15, 11, 84, 26, 125, 11, 6 };
            HashEncryptionParameters encryption = encrypt ? new(123, key, HashEncryptionAlgorithm.AES128) : null;

            int extraHashSections = 0;

            if (normalize)
                extraHashSections++;

            if (encrypt)
                extraHashSections++;

            var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 1000, encryption) { Normalize = normalize };

            string sha256Hash1000Iterations = hasher.Hash(Password);
            Assert.AreEqual(2 + extraHashSections, sha256Hash1000Iterations.Split(' ').Length);

            Assert.IsNull(hasher.Update(sha256Hash1000Iterations));
            Assert.IsFalse(hasher.RequiresUpdate(sha256Hash1000Iterations));
            Assert.IsFalse(hasher.RequiresRehash(sha256Hash1000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Iterations, Password));

            hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 3000, encryption) { Normalize = normalize };

            Assert.IsTrue(hasher.RequiresUpdate(sha256Hash1000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Iterations, Password));

            string sha256Hash1000Then2000Iterations = hasher.Update(sha256Hash1000Iterations)!;
            Assert.IsNotNull(sha256Hash1000Then2000Iterations);
            Assert.AreEqual(3 + extraHashSections, sha256Hash1000Then2000Iterations.Split(' ').Length);

            Assert.IsNull(hasher.Update(sha256Hash1000Then2000Iterations));
            Assert.IsFalse(hasher.RequiresUpdate(sha256Hash1000Then2000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Then2000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Then2000Iterations, Password));

            hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 8000, encryption) { Normalize = normalize };
            Assert.IsTrue(hasher.RequiresUpdate(sha256Hash1000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Then2000Iterations, Password));

            string sha256Hash1000Then2000Then5000Iterations = hasher.Update(sha256Hash1000Then2000Iterations)!;
            Assert.IsNotNull(sha256Hash1000Then2000Then5000Iterations);
            Assert.AreEqual(4 + extraHashSections, sha256Hash1000Then2000Then5000Iterations.Split(' ').Length);

            Assert.IsNull(hasher.Update(sha256Hash1000Then2000Then5000Iterations));
            Assert.IsFalse(hasher.RequiresUpdate(sha256Hash1000Then2000Then5000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Then2000Then5000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Then2000Then5000Iterations, Password));

            string sha256Hash1000Then7000Iterations = hasher.Update(sha256Hash1000Iterations)!;
            Assert.IsNotNull(sha256Hash1000Then7000Iterations);
            Assert.AreEqual(3 + extraHashSections, sha256Hash1000Then7000Iterations.Split(' ').Length);

            Assert.IsNull(hasher.Update(sha256Hash1000Then7000Iterations));
            Assert.IsFalse(hasher.RequiresUpdate(sha256Hash1000Then7000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha256Hash1000Then7000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha256Hash1000Then7000Iterations, Password));

            hasher = new PasswordHasher(PasswordHashAlgorithm.SHA512, 1000, encryption) { Normalize = normalize };
            hasher.AddLegacyHashAlgorithms(PasswordHashAlgorithm.SHA256);

            string sha512HashFromSha256Hash1000Iterations = hasher.Update(sha256Hash1000Iterations)!;
            Assert.IsNotNull(sha512HashFromSha256Hash1000Iterations);
            Assert.AreEqual(3 + extraHashSections, sha512HashFromSha256Hash1000Iterations.Split(' ').Length);

            Assert.IsNull(hasher.Update(sha512HashFromSha256Hash1000Iterations));
            Assert.IsFalse(hasher.RequiresUpdate(sha512HashFromSha256Hash1000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha512HashFromSha256Hash1000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha512HashFromSha256Hash1000Iterations, Password));

            string sha512HashFromsha256Hash1000Then7000Iterations = hasher.Update(sha256Hash1000Then7000Iterations)!;
            Assert.IsNotNull(sha512HashFromsha256Hash1000Then7000Iterations);
            Assert.AreEqual(4 + extraHashSections, sha512HashFromsha256Hash1000Then7000Iterations.Split(' ').Length);

            Assert.IsNull(hasher.Update(sha512HashFromsha256Hash1000Then7000Iterations));
            Assert.IsFalse(hasher.RequiresUpdate(sha512HashFromsha256Hash1000Then7000Iterations));
            Assert.IsTrue(hasher.RequiresRehash(sha512HashFromsha256Hash1000Then7000Iterations, Password));
            Assert.IsTrue(hasher.Verify(sha512HashFromsha256Hash1000Then7000Iterations, Password));
        }

        [TestMethod]
        public void UpdateMasterKey()
        {
            byte[] key1 = new byte[] { 43, 12, 64, 63, 1, 6, 74, 123, 4, 15, 11, 84, 26, 125, 11, 6 };
            HashEncryptionParameters encryption1 = new(123, key1, HashEncryptionAlgorithm.AES128);

            byte[] key2 = new byte[] { 44, 12, 64, 63, 1, 6, 74, 123, 4, 15, 11, 84, 26, 125, 11, 6 };
            HashEncryptionParameters encryption2 = new(456, key2, HashEncryptionAlgorithm.AES128);

            var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA512, 1000);

            string hash = hasher.Hash(Password);
            Assert.IsTrue(hasher.Verify(hash, Password));

            var hasher1 = new PasswordHasher(PasswordHashAlgorithm.SHA512, 1000, encryption1);
            Assert.IsTrue(hasher1.RequiresUpdate(hash));

            string hash1 = hasher1.Update(hash)!;
            Assert.AreNotEqual(hash1, hash);

            Assert.IsTrue(hasher1.Verify(hash1, Password));
            Assert.ThrowsException<FormatException>(() => hasher.Verify(hash1, Password));

            var hasher2_0 = new PasswordHasher(PasswordHashAlgorithm.SHA512, 1000, encryption2);
            Assert.IsTrue(hasher2_0.RequiresUpdate(hash));
            Assert.ThrowsException<FormatException>(() => hasher2_0.RequiresUpdate(hash1));

            string hash2_0 = hasher2_0.Update(hash)!;
            Assert.IsTrue(hasher2_0.Verify(hash2_0, Password));
            Assert.ThrowsException<FormatException>(() => hasher2_0.Update(hash1));

            var hasher2_1 = new PasswordHasher(PasswordHashAlgorithm.SHA512, 1000, encryption2);
            hasher2_1.AddLegacyEncryptionParameters(encryption1);
            Assert.IsTrue(hasher2_1.RequiresUpdate(hash));
            Assert.IsTrue(hasher2_1.RequiresUpdate(hash1));

            string hash2_1 = hasher2_1.Update(hash1)!;
            Assert.AreNotEqual(hash2_1, hash2_0); // AES IV values should be different for each encryption
            Assert.AreNotEqual(hash2_1, hash1);

            Assert.IsTrue(hasher2_1.Verify(hash, Password));
            Assert.IsTrue(hasher2_1.Verify(hash1, Password));
            Assert.IsTrue(hasher2_1.Verify(hash2_1, Password));
        }

        [TestMethod]
        public void Normalization()
        {
            var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA384, 100) { Normalize = false };

            string hash = hasher.Hash(Password);
            Assert.IsFalse(hasher.RequiresUpdate(hash));
            Assert.IsFalse(hasher.RequiresRehash(hash, Password));
            Assert.IsTrue(hasher.Verify(hash, Password));
            Assert.IsFalse(hasher.Verify(hash, PasswordWithNormalSpace));

            hasher.Normalize = true;
            Assert.IsFalse(hasher.RequiresUpdate(hash));
            Assert.IsTrue(hasher.RequiresRehash(hash, Password));

            hash = hasher.Hash(Password);
            Assert.IsTrue(hasher.Verify(hash, Password));
            Assert.IsTrue(hasher.Verify(hash, PasswordWithNormalSpace));
        }

        [TestMethod]
        public void RehashWithIllegalChars()
        {
            var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 200) { Normalize = false };
            string hash = hasher.Hash(PasswordWithIllegalChars);
            Assert.IsFalse(hash.StartsWith("!", StringComparison.Ordinal));
            Assert.IsTrue(hasher.Verify(hash, PasswordWithIllegalChars));
            Assert.IsFalse(hasher.RequiresRehash(hash, PasswordWithIllegalChars));

            hasher.Normalize = true;
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
            var hasher = new PasswordHasher(PasswordHashAlgorithm.SHA256, 200) { Normalize = false };
            string hash = hasher.Hash(Password);
            Assert.IsFalse(hash.StartsWith("!", StringComparison.Ordinal));
            Assert.IsTrue(hasher.Verify(hash, Password));

            hasher.Normalize = true;
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
