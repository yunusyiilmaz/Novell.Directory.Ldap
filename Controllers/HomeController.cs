using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using Novell.Directory.LdapService.Models;
using Novell.Directory.LdapService.Service;

namespace Novell.Directory.LdapService.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }
        [HttpPost]
        public IActionResult Index(string userName,string password)
        {
            LdapServices auth = new LdapServices();
            var serverControl = auth.isServerReachable();
            string result;
            if(serverControl==false)
            {
                result = "Login Fail";

            }
            if(auth.Authenticated(userName,password,out LdapAuthenticationViewModel userProfile))
            {
                return View("Index",userProfile);
            }
            else
            {
                result = "Login Fail";
            }
            return View("Index", result);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}