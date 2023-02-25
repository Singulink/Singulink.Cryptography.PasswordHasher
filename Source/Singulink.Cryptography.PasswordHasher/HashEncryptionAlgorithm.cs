using System.Security.Cryptography;

namespace Singulink.Cryptography;

/// <summary>
/// Provides methods to encrypt and decrypt password hashes.
/// </summary>
public abstract class HashEncryptionAlgorithm
{
    private static readonly RNGCryptoServiceProvider CryptoRandom = new();

    /// <summary>
    /// Gets the AES password hash encyption algorithm that uses a 128-bit master key. A randomly generated 128-bit IV is prepended to the output.
    /// </summary>
    public static HashEncryptionAlgorithm AES128 { get; } = new Aes128();

    /// <summary>
    /// Determines whether a key with the given size (in bytes) is valid for the hash encryption algorithm.
    /// </summary>
    public abstract bool IsValidKeySize(int size);

    /// <summary>
    /// Encrypts the provided data and returns the result.
    /// </summary>
    public abstract byte[] Encrypt(byte[] key, byte[] data);

    /// <summary>
    /// Decrypts the provided data and returns the result.
    /// </summary>
    public abstract byte[] Decrypt(byte[] key, byte[] encryptedData);

    private class Aes128 : HashEncryptionAlgorithm
    {
        private const int IvSize = 16;

        public override bool IsValidKeySize(int size) => size == 16;

        /// <inheritdoc />
        public override byte[] Encrypt(byte[] key, byte[] data)
        {
            using var aes = Aes.Create();

            if (!IsValidKeySize(key.Length))
                throw new ArgumentException("Key is not a valid size for AES encryption.", nameof(key));

            byte[] iv = new byte[IvSize];
            CryptoRandom.GetBytes(iv);

            ICryptoTransform encryptor = aes.CreateEncryptor(key, iv);

            using var memoryStream = new MemoryStream();
            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
            {
                memoryStream.Write(iv);
                cryptoStream.Write(data);
            }

            return memoryStream.ToArray();
        }

        /// <inheritdoc />
        public override byte[] Decrypt(byte[] key, byte[] encryptedData)
        {
            using var aes = Aes.Create();

            if (!IsValidKeySize(key.Length))
                throw new ArgumentException("Key is not a valid size for AES encryption.", nameof(key));

            if (encryptedData.Length <= IvSize)
                throw new CryptographicException("Encrypted data does not contain a valid length IV.");

            byte[] iv = new byte[IvSize];
            using var memoryStream = new MemoryStream(encryptedData);
            memoryStream.Read(iv);

            ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);

            using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            using var outputStream = new MemoryStream();

            cryptoStream.CopyTo(outputStream);
            return outputStream.ToArray();
        }
    }
}