using System;
using System.Collections.Generic;
using System.Text;

namespace Singulink.Cryptography
{
    /// <summary>
    /// Specifies different modes of checking letters for category matches.
    /// </summary>
    public enum LetterCategoryMode
    {
        /// <summary>
        /// Indicates that uppercase letters, lowercase letters, and other letters (i.e. asian characters) qualify as 3 separate matched categories.
        /// </summary>
        ThreeCategories,

        /// <summary>
        /// Indicates that uppercase letters and lowercase letters quality as 2 separate matched categories. If the password contains only 1 of those other
        /// letters (i.e. asian characters) fulfill the requirement to match the other category.
        /// </summary>
        TwoCategories,

        /// <summary>
        /// Indicates that letters qualify as a single matched category.
        /// </summary>
        OneCategory,

        /// <summary>
        /// Checking of letters is skipped and does not contribute to category matches.
        /// </summary>
        None,
    }
}
