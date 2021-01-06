using System;
using System.Globalization;
using System.Text;
using System.Unicode;

namespace Singulink.Cryptography
{
    /// <summary>
    /// Provides RFC 8265/RFC 7613 compliant password normalization.
    /// </summary>
    public static class PasswordNormalizer
    {
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

            // Note: IsControlLCategory() already handles disallowing JoinControl characters.

            // TODO: add contextual rules for the above.

            for (int i = 0; i < s.Length; i += char.IsSurrogatePair(s, i) ? 2 : 1) {
                int cp = char.ConvertToUtf32(s, i);

                if (IsPValidException(cp))
                    continue;

                if (IsDisallowedException(cp) || IsOldHangulJamoICategory(cp) || IsIgnorablePropertiesMCategory(cp))
                    return false;

                var uc = CharUnicodeInfo.GetUnicodeCategory(cp);

                if (IsControlLCategory(uc) || IsUnassignedCategory(uc))
                    return false;
            }

            return true;
        }

        private static bool IsOldHangulJamoICategory(int codePoint)
        {
            // http://www.unicode.org/Public/UCD/latest/ucd/HangulSyllableType.txt
            // # Hangul_Syllable_Type=Leading_Jamo

            // 1100..115F    ; L # Lo  [96] HANGUL CHOSEONG KIYEOK..HANGUL CHOSEONG FILLER
            // A960..A97C    ; L # Lo  [29] HANGUL CHOSEONG TIKEUT-MIEUM..HANGUL CHOSEONG SSANGYEORINHIEUH

            // # Total code points: 125

            // # ================================================

            // # Hangul_Syllable_Type=Vowel_Jamo

            // 1160..11A7    ; V # Lo  [72] HANGUL JUNGSEONG FILLER..HANGUL JUNGSEONG O-YAE
            // D7B0..D7C6    ; V # Lo  [23] HANGUL JUNGSEONG O-YEO..HANGUL JUNGSEONG ARAEA-E

            // # Total code points: 95

            // # ================================================

            // # Hangul_Syllable_Type=Trailing_Jamo

            // 11A8..11FF    ; T # Lo  [88] HANGUL JONGSEONG KIYEOK..HANGUL JONGSEONG SSANGNIEUN
            // D7CB..D7FB    ; T # Lo  [49] HANGUL JONGSEONG NIEUN-RIEUL..HANGUL JONGSEONG PHIEUPH-THIEUTH

            // # Total code points: 137

            return codePoint is (>= 0x1100 and <= 0x115F)
                             or (>= 0xA960 and <= 0xA97C)
                             or (>= 0x1160 and <= 0x11A7)
                             or (>= 0xD7B0 and <= 0xD7C6)
                             or (>= 0x11A8 and <= 0x11FF)
                             or (>= 0xD7CB and <= 0xD7FB);
        }

        private static bool IsControlLCategory(UnicodeCategory category) => category == UnicodeCategory.Control;

        private static bool IsIgnorablePropertiesMCategory(int codePoint)
        {
            // M: Default_Ignorable_Code_Point(cp) = True or Noncharacter_Code_Point(cp) = True

            var charProps = UnicodeInfo.GetCharInfo(codePoint).ContributoryProperties;

            return (charProps & ContributoryProperties.NonCharacterCodePoint) != 0 ||
                   (charProps & ContributoryProperties.OtherDefaultIgnorableCodePoint) != 0;
        }

        private static bool IsUnassignedCategory(UnicodeCategory category) => category == UnicodeCategory.OtherNotAssigned;

        private static bool IsPValidException(int codePoint)
        {
            // RFC 5892 Section 2.6 (Exceptions)

            // PVALID -- Would otherwise have been DISALLOWED

            // 00DF; PVALID     # LATIN SMALL LETTER SHARP S
            // 03C2; PVALID     # GREEK SMALL LETTER FINAL SIGMA
            // 06FD; PVALID     # ARABIC SIGN SINDHI AMPERSAND
            // 06FE; PVALID     # ARABIC SIGN SINDHI POSTPOSITION MEN
            // 0F0B; PVALID     # TIBETAN MARK INTERSYLLABIC TSHEG
            // 3007; PVALID     # IDEOGRAPHIC NUMBER ZERO

            switch (codePoint) {
                case 0x00DF:
                case 0x03C2:
                case 0x06FD:
                case 0x06FE:
                case 0x0F0B:
                case 0x3007:
                    return true;
                default:
                    return false;
            }

            // Ignore these, context required:

            // CONTEXTO -- Would otherwise have been DISALLOWED

            // 00B7; CONTEXTO   # MIDDLE DOT
            // 0375; CONTEXTO   # GREEK LOWER NUMERAL SIGN (KERAIA)
            // 05F3; CONTEXTO   # HEBREW PUNCTUATION GERESH
            // 05F4; CONTEXTO   # HEBREW PUNCTUATION GERSHAYIM
            // 30FB; CONTEXTO   # KATAKANA MIDDLE DOT
        }

        private static bool IsDisallowedException(int codePoint)
        {
            // Disallow any chars that need context

            // RFC 5892 Section 2.6 (Exceptions)

            // CONTEXTO -- Would otherwise have been PVALID

            // 0660; CONTEXTO   # ARABIC-INDIC DIGIT ZERO
            // 0661; CONTEXTO   # ARABIC-INDIC DIGIT ONE
            // 0662; CONTEXTO   # ARABIC-INDIC DIGIT TWO
            // 0663; CONTEXTO   # ARABIC-INDIC DIGIT THREE
            // 0664; CONTEXTO   # ARABIC-INDIC DIGIT FOUR
            // 0665; CONTEXTO   # ARABIC-INDIC DIGIT FIVE
            // 0666; CONTEXTO   # ARABIC-INDIC DIGIT SIX
            // 0667; CONTEXTO   # ARABIC-INDIC DIGIT SEVEN
            // 0668; CONTEXTO   # ARABIC-INDIC DIGIT EIGHT
            // 0669; CONTEXTO   # ARABIC-INDIC DIGIT NINE
            // 06F0; CONTEXTO   # EXTENDED ARABIC-INDIC DIGIT ZERO
            // 06F1; CONTEXTO   # EXTENDED ARABIC-INDIC DIGIT ONE
            // 06F2; CONTEXTO   # EXTENDED ARABIC-INDIC DIGIT TWO
            // 06F3; CONTEXTO   # EXTENDED ARABIC-INDIC DIGIT THREE
            // 06F4; CONTEXTO   # EXTENDED ARABIC-INDIC DIGIT FOUR
            // 06F5; CONTEXTO   # EXTENDED ARABIC-INDIC DIGIT FIVE
            // 06F6; CONTEXTO   # EXTENDED ARABIC-INDIC DIGIT SIX
            // 06F7; CONTEXTO   # EXTENDED ARABIC-INDIC DIGIT SEVEN
            // 06F8; CONTEXTO   # EXTENDED ARABIC-INDIC DIGIT EIGHT
            // 06F9; CONTEXTO   # EXTENDED ARABIC-INDIC DIGIT NINE

            // DISALLOWED -- Would otherwise have been PVALID

            // 0640; DISALLOWED # ARABIC TATWEEL
            // 07FA; DISALLOWED # NKO LAJANYALAN
            // 302E; DISALLOWED # HANGUL SINGLE DOT TONE MARK
            // 302F; DISALLOWED # HANGUL DOUBLE DOT TONE MARK
            // 3031; DISALLOWED # VERTICAL KANA REPEAT MARK
            // 3032; DISALLOWED # VERTICAL KANA REPEAT WITH VOICED SOUND MARK
            // 3033; DISALLOWED # VERTICAL KANA REPEAT MARK UPPER HALF
            // 3034; DISALLOWED # VERTICAL KANA REPEAT WITH VOICED SOUND MARK UPPER HA
            // 3035; DISALLOWED # VERTICAL KANA REPEAT MARK LOWER HALF
            // 303B; DISALLOWED # VERTICAL IDEOGRAPHIC ITERATION MARK

            switch (codePoint) {
                case 0x0660:
                case 0x0661:
                case 0x0662:
                case 0x0663:
                case 0x0664:
                case 0x0665:
                case 0x0666:
                case 0x0667:
                case 0x0668:
                case 0x0669:
                case 0x06F0:
                case 0x06F1:
                case 0x06F2:
                case 0x06F3:
                case 0x06F4:
                case 0x06F5:
                case 0x06F6:
                case 0x06F7:
                case 0x06F8:
                case 0x06F9:
                case 0x0640:
                case 0x07FA:
                case 0x302E:
                case 0x302F:
                case 0x3031:
                case 0x3032:
                case 0x3033:
                case 0x3034:
                case 0x3035:
                case 0x303B:
                    return true;
                default:
                    return false;
            }
        }

        #endregion
    }
}
