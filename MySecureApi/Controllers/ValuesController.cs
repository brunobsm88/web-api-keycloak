using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace MySecureApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        private readonly ILogger<ValuesController> _logger;

        public ValuesController(ILogger<ValuesController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        [Authorize(Roles = "admin")]
        [Route("get-admin")]
        public IActionResult GetAdmin()
        {
            _logger.LogInformation("Admin endpoint accessed.");
            var userRoles = User.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);
            _logger.LogInformation("User roles: {Roles}", string.Join(", ", userRoles));
            return Ok("You are admin.");
        }

        [HttpGet]
        [Authorize(Roles = "general")]
        [Route("get-general")]
        public IActionResult GetGeneral()
        {
            _logger.LogInformation("General endpoint accessed.");
            var userRoles = User.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);
            _logger.LogInformation("User roles: {Roles}", string.Join(", ", userRoles));
            return Ok("You are general.");
        }

        [HttpGet]
        [Authorize]
        [Route("get-all")]
        public IActionResult GetAll()
        {
            _logger.LogInformation("All endpoint accessed.");
            var userRoles = User.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);
            _logger.LogInformation("User roles: {Roles}", string.Join(", ", userRoles));
            return Ok("You are all.");
        }
    }
}
