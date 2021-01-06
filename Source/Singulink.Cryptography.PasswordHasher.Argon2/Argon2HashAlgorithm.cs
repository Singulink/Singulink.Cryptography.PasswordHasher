using System;
using Konscious.Security.Cryptography;

namespace Singulink.Cryptography
{
    /// <summary>
    /// Provides Argon2i, Argon2d and Argon2id password hashing functionality.
    /// </summary>
    public sealed class Argon2HashAlgorithm : PasswordHashAlgorithm
    {
        /// <summary>
        /// Gets the Argon2 algorithm type.
        /// </summary>
        public Argon2Type Type { get; }

        /// <summary>
        /// Gets the number of lanes used while processing the hash.
        /// </summary>
        public int DegreeOfParallelism { get; }

        /// <summary>
        /// Gets the amount of memory (in MB) used while processing the hash.
        /// </summary>
        public int MemorySize { get; }

        /// <summary>
        /// Gets the hash output size in bytes.
        /// </summary>
        public int OutputSize { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="Argon2HashAlgorithm"/> class with the specified parameters.
        /// </summary>
        /// <param name="type">The Argon2 algorithm type to use.</param>
        /// <param name="degreeOfParallelism">The number of lanes to use while processing the hash.</param>
        /// <param name="memorySize">The amount of memory (in MB) to use while processing the hash.</param>
        /// <param name="outputSize">The size of the output hash (in bytes). 16 bytes is recommended.</param>
        public Argon2HashAlgorithm(Argon2Type type, int degreeOfParallelism, int memorySize, int outputSize = 16) : base($"{type}{outputSize * 8}-{degreeOfParallelism}P-{memorySize}MB")
        {
            if (!Enum.IsDefined(typeof(Argon2Type), type))
                throw new ArgumentOutOfRangeException(nameof(type));

            if (degreeOfParallelism < 1)
                throw new ArgumentOutOfRangeException(nameof(degreeOfParallelism));

            if (memorySize < 1)
                throw new ArgumentOutOfRangeException(nameof(memorySize));

            if (outputSize < 1)
                throw new ArgumentOutOfRangeException(nameof(outputSize));

            DegreeOfParallelism = degreeOfParallelism;
            MemorySize = memorySize;
            OutputSize = outputSize;
        }

        /// <inheritdoc/>
        public override byte[] Hash(byte[] password, byte[] salt, int iterations)
        {
            using Argon2 argon2 = Type switch {
                Argon2Type.Argon2i => new Argon2i(password),
                Argon2Type.Argon2d => new Argon2d(password),
                _ => new Argon2id(password),
            };

            argon2.DegreeOfParallelism = DegreeOfParallelism;
            argon2.MemorySize = MemorySize * 1024;
            argon2.Salt = salt;
            argon2.Iterations = iterations;

            return argon2.GetBytes(OutputSize);
        }
    }
}
