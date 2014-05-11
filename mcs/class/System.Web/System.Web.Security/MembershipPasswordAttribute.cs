using System;
using System.ComponentModel.DataAnnotations;
using System.Web.Security;
using System.Linq;
using System.Text.RegularExpressions;

namespace System.Web.Security
{
	[AttributeUsage(
		AttributeTargets.Property | AttributeTargets.Field | 
		AttributeTargets.Parameter, AllowMultiple = false)]
	public class MembershipPasswordAttribute : ValidationAttribute
	{
		private Int32? _minRequiredPasswordLength;
		private Int32? _minRequiredNonAlphanumericCharacters;
		private String _passwordStrengthRegularExpression;

		private readonly String _minRequiredPasswordLengthError =
			"{0} must have at least {1} characters";

		private readonly String _minNonAlphanumericCharactersError = 
			"{0} must have at least {1} special characters";

		private readonly String _passwordStrengthError = 
			"{0} is week";

		public MembershipPasswordAttribute()
		{
			MinPasswordLengthError = _minRequiredPasswordLengthError;
			MinNonAlphanumericCharactersError = _minNonAlphanumericCharactersError;
			PasswordStrengthError = _passwordStrengthError;
		}

		public int MinRequiredPasswordLength
		{
			get
			{
				return !_minRequiredPasswordLength.HasValue ? 
					Membership.Provider.MinRequiredPasswordLength : 
					_minRequiredPasswordLength.Value;
			}
			set
			{
				_minRequiredPasswordLength = value;
			}
		}

		public int MinRequiredNonAlphanumericCharacters
		{
			get
			{
				return !_minRequiredNonAlphanumericCharacters.HasValue ? 
					Membership.Provider.MinRequiredNonAlphanumericCharacters : 
					_minRequiredNonAlphanumericCharacters.Value;
			}
			set
			{
				_minRequiredNonAlphanumericCharacters = value;
			}
		}

		public String PasswordStrengthRegularExpression
		{
			get
			{
				return _passwordStrengthRegularExpression ?? 
					Membership.Provider.PasswordStrengthRegularExpression;
			}
			set
			{
				_passwordStrengthRegularExpression = value;
			}
		}

		public Type ResourceType { get; set; }
		public String MinPasswordLengthError { get; set; }
		public String MinNonAlphanumericCharactersError { get; set; }
		public String PasswordStrengthError { get; set; }

		protected override ValidationResult IsValid(Object value, ValidationContext validationContext)
		{
			var password = (value as String) ?? String.Empty;
			var displayName = String.Empty;

			if(validationContext != null)
			{
				displayName = validationContext.MemberName;
				if (validationContext.DisplayName != null)
					displayName = validationContext.DisplayName;
			}

			if (String.IsNullOrEmpty(password))
				return ValidationResult.Success;

			if (password.Length < MinRequiredPasswordLength)
			{
				return new ValidationResult(String.Format(
					MinPasswordLengthError, displayName, MinRequiredPasswordLength));
			}

			if (MinRequiredNonAlphanumericCharacters > 0)
			{
				var nonAlphaNumCount = password.Count(c => !Char.IsLetterOrDigit(c));

				if (nonAlphaNumCount < MinRequiredNonAlphanumericCharacters)
				{
					return new ValidationResult(String.Format(
						MinNonAlphanumericCharactersError, displayName, MinRequiredPasswordLength));
				}
			}

			if (PasswordStrengthRegularExpression != null)
			{
				var regex = new Regex(PasswordStrengthRegularExpression);
				if (!regex.IsMatch(password))
				{
					return new ValidationResult(String.Format(
						PasswordStrengthError, displayName, MinRequiredPasswordLength));
				}
			}

			return ValidationResult.Success;
		}
	}
}