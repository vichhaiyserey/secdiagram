using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Exposure.Api;

[ApiController]
[Authorize]
[Route("api/admin")]
public class AdminController : ControllerBase
{
    // Authenticated (class-level [Authorize]).
    [HttpPost("run")]
    public IActionResult Run([FromQuery] string job)
    {
        Process.Start("/usr/bin/job", job);
        return Ok();
    }

    // Explicitly public: [AllowAnonymous] overrides the class.
    [AllowAnonymous]
    [HttpPost("ping")]
    public IActionResult Ping([FromQuery] string host)
    {
        Process.Start("/bin/ping", host);
        return Ok();
    }
}
