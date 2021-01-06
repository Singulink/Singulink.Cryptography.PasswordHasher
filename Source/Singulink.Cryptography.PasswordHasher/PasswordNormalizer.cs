using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Text;
using Singulink.Cryptography.Unicode;

namespace Singulink.Cryptography
{
    /// <summary>
    /// Provides RFC 8265/RFC 7613 compliant password normalization.
    /// </summary>
    public static class PasswordNormalizer
    {
        private static readonly (int Start, int End)[] _defaultIgnorableRanges;
        private static readonly (int Start, int End)[] _exceptionsAllowRanges;
        private static readonly (int Start, int End)[] _exceptionsDisallowRanges;
        private static readonly (int Start, int End)[] _oldHangulJamoRanges;

        [SuppressMessage("Performance", "CA1810:Initialize reference type static fields inline", Justification = "Not performance sensitive")]
        static PasswordNormalizer()
        {
            const string PValidExceptionValue = "PVALID";

            var assembly = typeof(PasswordNormalizer).Assembly;
            string prefix = typeof(UnicodeData).Namespace! + ".Data.";

            var defaultIgnorableData = UnicodeData.Load(assembly.GetManifestResourceStream(prefix + "Default_Ignorable_DerivedProperty.txt")!);
            _defaultIgnorableRanges = defaultIgnorableData.Items.Select(x => (x.Start, x.End)).ToArray();

            // PVALID exceptions are added to the allow list, everything else (including context-required items) is added to disallow list

            var exceptionData = UnicodeData.Load(assembly.GetManifestResourceStream(prefix + "RFC5892_Exceptions_FCategory.txt")!);
            _exceptionsAllowRanges = exceptionData.Items.Where(x => x.Value == PValidExceptionValue).Select(x => (x.Start, x.End)).ToArray();
            _exceptionsDisallowRanges = exceptionData.Items.Where(x => x.Value != PValidExceptionValue).Select(x => (x.Start, x.End)).ToArray();

            var oldHangulJamoData = UnicodeData.Load(assembly.GetManifestResourceStream(prefix + "RFC5892_OldHangulJamo_ICategory.txt")!);
            _oldHangulJamoRanges = defaultIgnorableData.Items.Select(x => (x.Start, x.End)).ToArray();

            Debug.Assert(_defaultIgnorableRanges.Length > 0, "unicode data not loaded properly");
            Debug.Assert(_exceptionsAllowRanges.Length > 0, "unicode data not loaded properly");
            Debug.Assert(_exceptionsDisallowRanges.Length > 0, "unicode data not loaded properly");
            Debug.Assert(_oldHangulJamoRanges.Length > 0, "unicode data not loaded properly");
        }

        /// <summary>
        /// Normalizes the given password.
        /// </summary>
        /// <exception cref="ArgumentException">
        /// The password contains invalid unicode characters or characters that are disallowed in the Freeform class as per RFC 8264.
        /// </exception>
        public static string Normalize(string password)
        {
            // RFC 8265 section 4.2.2 (OpaqueString profile):

            // 1. Width-Mapping Rule: Fullwidth and halfwidth characters MUST NOT be mapped to their decomposition mappings (see Unicode Standard Annex #11
            //    [UAX11]).

            // 2. Additional Mapping Rule: Any instances of non-ASCII space MUST be mapped to ASCII space (U+0020); a non-ASCII space is any Unicode code point
            //    having a Unicode general category of "Zs"(with the exception of U+0020).

            for (int i = 0; i < password.Length; i++) {
                // All space chars are in the BMP so don't worry about surrogates
                char c = password[i];

                if (c != ' ' && CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.SpaceSeparator)
                    password = password.Replace(c, ' ');
            }

            // 3. Case-Mapping Rule: Uppercase and titlecase characters MUST NOT be mapped to their lowercase equivalents.

            // 4. Normalization Rule: Unicode Normalization Form C (NFC) MUST be applied to all characters.

            try {
                password = password.Normalize(NormalizationForm.FormC);
            }
            catch (ArgumentException) {
                throw new ArgumentException("Password is not a valid unicode string.", nameof(password));
            }

            // 5. Directionality Rule: There is no directionality rule.  The "Bidi Rule" (defined in [RFC5893]) and similar rules are unnecessary and
            //    inapplicable to passwords, because they can reduce the range of characters that are allowed in a string and therefore reduce the amount of
            //    entropy that is possible in a password.  Such rules are intended to minimize the possibility that the same string will be displayed
            //    differently on a layout system set for right-to-left display and a layout system set for left-to-right display; however, passwords are
            //    typically not displayed at all and are rarely meant to be interoperable across different layout systems in the way that non-secret strings
            //    like domain names and usernames are.  Furthermore, it is perfectly acceptable for opaque strings other than passwords to be presented
            //    differently in different layout systems, as long as the presentation is consistent in any given layout system.

            // RFC 8265 section 4.2.1 (Preparation)
            // An entity that prepares a string according to this profile MUST ensure that the string consists only of Unicode code points that conform to the
            // FreeformClass base string class defined in [RFC7564].

            if (!IsFreeformClassCompliant(password))
                throw new ArgumentException("Password contains disallowed characters.", nameof(password));

            return password;
        }

        #region RFC 8264 Freeform Class

        private static bool IsFreeformClassCompliant(string s)
        {
            // RFC 8264

            // 4.3.2.  Contextual Rule Required
            //    o  A number of characters from the Exceptions ("F") category defined under Section 9.6 (see Section 9.6 for a full list).
            //    o  Joining characters, i.e., the JoinControl ("H") category defined under Section 9.8.

            // 4.3.3.  Disallowed
            //    o  Old Hangul Jamo characters, i.e., the OldHangulJamo ("I") category defined under Section 9.9.
            //    o  Control characters, i.e., the Controls ("L") category defined under Section 9.12.
            //    o  Ignorable characters, i.e., the PrecisIgnorableProperties ("M") category defined under Section 9.13.

            // 4.3.4.  Unassigned
            //    Any code points that are not yet designated in the Unicode character set are considered unassigned for purposes of the FreeformClass, and
            //    such code points are to be treated as disallowed.

            // We disallow any "context required" characters as per section 8 of RFC 8264:

            // CONTEXTUAL RULE REQUIRED  Some characteristics of the character, such as its being invisible in certain contexts or problematic in others,
            //    require that it not be used in labels unless specific other characters or properties are present.  As in IDNA2008, there are two subdivisions
            //    of CONTEXTUAL RULE REQUIRED -- the first for Join_controls (called "CONTEXTJ") and the second for other characters (called "CONTEXTO").  A
            //    character with the derived property value CONTEXTJ or CONTEXTO MUST NOT be used unless an appropriate rule has been established and the
            //    context of the character is consistent with that rule.  The most notable of the CONTEXTUAL RULE REQUIRED characters are the Join Control
            //    characters U+200D ZERO WIDTH JOINER and U+200C ZERO WIDTH NON-JOINER, which have a derived property value of CONTEXTJ.  See Appendix A of
            //    [RFC5892] for more information.

            // TODO: add contextual rules for the above to allow more characters.

            for (int i = 0; i < s.Length; i += char.IsSurrogatePair(s, i) ? 2 : 1) {
                int cp = char.ConvertToUtf32(s, i);

                if (_exceptionsAllowRanges.Contains(cp))
                    continue;

                if (_exceptionsDisallowRanges.Contains(cp) || _oldHangulJamoRanges.Contains(cp))
                    return false;

                var uc = CharUnicodeInfo.GetUnicodeCategory(cp);

                // Control characters and unassigned characters is covered by the category below + FormC normalization
                // JoinControl is a subcategory of Control so that is handled as disallowed as well.

                if (IsIgnorablePropertiesMCategory(cp, uc))
                    return false;
            }

            return true;
        }

        private static bool IsIgnorablePropertiesMCategory(int codePoint, UnicodeCategory category)
        {
            // M: Default_Ignorable_Code_Point(cp) = True or Noncharacter_Code_Point(cp) = True

            return _defaultIgnorableRanges.Contains(codePoint) || IsNonCharacterCodePoint(category);

            static bool IsNonCharacterCodePoint(UnicodeCategory category)
            {
                // From https://unicode.org/reports/tr44/

                switch (category) {
                    case UnicodeCategory.OtherNotAssigned:
                    case UnicodeCategory.Control:
                    case UnicodeCategory.PrivateUse:
                    case UnicodeCategory.Surrogate:
                        return true;
                    default:
                        return false;
                }
            }
        }

        private static bool Contains(this IEnumerable<(int Start, int End)> source, int codePoint)
        {
            foreach ((int start, int end) in source) {
                if (codePoint >= start && codePoint <= end)
                    return true;
            }

            return false;
        }

        #endregion
    }
}
