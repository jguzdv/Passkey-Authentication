using JGUZDV.PasskeyAuth.Resources;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Localization;

namespace JGUZDV.PasskeyAuth.Pages;

public class ErrorModel : PageModel
{
    private readonly ILogger<ErrorModel> _logger;
    private readonly IStringLocalizer<Shared> _sl;

    [BindProperty(SupportsGet = true)]
    public int? ErrorStatusCode { get; set; }

    public string? ErrorMessage { get; set; }

    public ErrorModel(ILogger<ErrorModel> logger, IStringLocalizer<Shared> sl)
    {
        _logger = logger;
        _sl = sl;
    }

    public void OnGet()
    {
        if (ErrorStatusCode.HasValue)
        {
            var errorResource = _sl[$"StatusCode:{ErrorStatusCode.Value}"];

            ErrorMessage = errorResource.ResourceNotFound ? _sl["StatusCode:Generic", ErrorStatusCode.Value] : errorResource.Value;
            return;
        }

        if (HttpContext.Features.Get<IExceptionHandlerFeature>()?.Error is BadHttpRequestException httpExc)
        {
            var errorResource = _sl[httpExc.Message];

            ErrorMessage = errorResource.ResourceNotFound ? _sl["StatusCode:400"] : errorResource.Value;
            return;
        }
    }
}
