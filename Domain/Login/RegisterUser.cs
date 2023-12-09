using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace Domain.Login;
public class RegisterUser
{
    [Required(ErrorMessage = "User Name is required")]
    public string? UserName { get; set; }    

    [EmailAddress]
    public string? Email { get; set; }
    
    [Required(ErrorMessage = "Password is required")]
    public string? Password { get; set; }
}