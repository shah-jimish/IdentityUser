using Microsoft.AspNetCore.Mvc;

namespace WebApi.Controller
{
    [ApiController]
    [Route("api/[controller]")]
    public class TestController : ControllerBase
    {
        [HttpGet("GetResponse")]
        public ActionResult GetResponse()
        {
            return Ok();
        }
    }
}
