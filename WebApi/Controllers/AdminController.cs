using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApi.Controller
{
    [Authorize(Roles = "Admin")]
    [ApiController]
    [Route("api/[controller]")]
    public class AdminController : ControllerBase
    {
        [HttpGet("EmployeeList")]
        public IEnumerable<string> GetEmployeeList()
        {
            return new List<string> { "user1", "user2", "user3" };
        }
    }
}