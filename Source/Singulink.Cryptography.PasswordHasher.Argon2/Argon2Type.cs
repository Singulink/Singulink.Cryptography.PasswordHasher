using System;
using System.Collections.Generic;
using System.Text;

namespace Singulink.Cryptography
{
    /// <summary>
    /// Specifies the Argon2 algorithm type.
    /// </summary>
    public enum Argon2Type
    {
        /// <summary>
        /// Specifies that the Argon2d algorithm will be used.
        /// </summary>
        Argon2d = 0,

        /// <summary>
        /// Specifies that the Argon2i algorithm will be used.
        /// </summary>
        Argon2i = 1,

        /// <summary>
        /// Specifies that the Argon2id algorithm will be used.
        /// </summary>
        Argon2id = 2,
    }
}
