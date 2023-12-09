using System.ComponentModel.DataAnnotations;

namespace Domain.Signup;
public class ResetPassword
{
    [Required]
    public string Password { get; set; } = null!;
    [Compare("Password", ErrorMessage = "The Password and confirm password does not match")]
    public string ConfirmPassword { get; set; } = null!;
    public string? Email { get; set; }
    public string? Token { get; set; }
}