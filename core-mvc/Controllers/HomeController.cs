using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using core_mvc.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Net.Http;

namespace core_mvc.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            List<IndexModel> listMeals = new List<IndexModel>();
            using (SqlConnection sqlConnection = new SqlConnection("Data Source = 188.121.44.217; Initial Catalog = clinicampus; User Id = User_clinicampus; Password = Napoleonx2;"))
            {
                using (SqlCommand sqlCommand = new SqlCommand("sp_SearchedComments", sqlConnection))
                {
                    sqlCommand.CommandType = System.Data.CommandType.StoredProcedure;
                    sqlCommand.Parameters.AddWithValue("@SearchTerm", "");
                    sqlConnection.Open();
                    SqlDataReader sqlReader = sqlCommand.ExecuteReader();
                    while (sqlReader.Read())
                    {
                        listMeals.Add(new IndexModel
                        {
                            dni = Convert.ToString(sqlReader[1]),
                            plantaDesc = Convert.ToString(sqlReader[0]),
                            //Comments = Convert.ToString(sqlReader[2]),
                            //ImageUrl = Convert.ToString(sqlReader[3]),
                            //Price = Convert.ToString(sqlReader[4])
                        });
                    }
                }
            }
            return View();
        }
        public IActionResult Index2()
        {
            var googleUID = GetStringClaimValueFromType("token");
            return View();
        }

        [HttpPost]
        public ActionResult postcode(string code)
        {
            try
            {
                return Json(new
                {
                    msg = "Successfully added " + code
                });
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        public class googleDetailsModel
        {
            public string displayName { get; set; }
            public string email { get; set; }
            public string photoURL { get; set; }
            public bool isAnonymous { get; set; }
            public string uid { get; set; }
            public bool emailVerified { get; set; }
            public string token { get; set; }
            public List<ProviderDataModel> providerData { get; set; }
        }
        public class ProviderDataModel
        {
            public string displayName { get; set; }
            public string email { get; set; }
            public string photoURL { get; set; }
            public string providerId { get; set; }
            public string uid { get; set; }
        }
        [Authorize]
        [CheckAuthorization]
        [HttpPost]       
        public async Task<JsonResult> googleDetails(googleDetailsModel code)
        {
           try
             {
                if (!string.IsNullOrEmpty(code.token))
                {
                    // por ejemplo rol o cualquier otro datoesta en HttpContext ((System.Security.Claims.ClaimsIdentity)HttpContext.User.Identity).RoleClaimType
                    // var schemeName = "";
                    // Create the identity from the user info
                    var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme, code.email, "1");  //ese 1 es el rol
                    identity.AddClaim(new Claim("displayName", code.displayName));
                    identity.AddClaim(new Claim("email", code.email));
                    identity.AddClaim(new Claim("uid", code.uid));
                    identity.AddClaim(new Claim("photoURL", code.photoURL));
                    identity.AddClaim(new Claim("uid", code.uid));
                    identity.AddClaim(new Claim("token", code.token));
                    var principal = new ClaimsPrincipal(identity);
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, new AuthenticationProperties { IsPersistent = true, ExpiresUtc = DateTime.UtcNow.AddDays(25) });
                        //  result.url = Url.Action("Dashboard", "Dashboard", new { area = "admin" }); ;


                        return Json(new
                    {
                        msg = "Successfully added " + code
                    });
                }
                else
                    return Json(new
                    {
                        msg = "Error while adding"
                    });
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public Int64 GetClaimValueFromType(string type)
        {
            string value = User.Claims.Where(c => c.Type == type)
                   .Select(c => c.Value).SingleOrDefault();
            return Convert.ToInt64(value);
        }
        public string GetStringClaimValueFromType(string type)
        {
            string value = User.Claims.Where(c => c.Type == type)
                   .Select(c => c.Value).SingleOrDefault();
            return value;
        }

        public Claim GetClaimFromType(string type)
        {
            return User.Claims.Where(c => c.Type == type)
                              .SingleOrDefault();
        }

        public void UpdateClaimValueByType(string type, string value)
        {
            var user = User as ClaimsPrincipal;
            var identity = user.Identity as ClaimsIdentity;
            var claim = User.Claims.Where(c => c.Type == type)
                              .SingleOrDefault();
            if (claim != null)
            {
                identity.RemoveClaim(claim);
                identity.AddClaim(new Claim(type, value));
            }
        }

        public class IndexModel
        {
            //public int id { get; set; } 
            public string dni { get; set; }
            public string plantaDesc { get; set; }

        }







        /// <summary>
        /// Authorization process in which all the headers are tested.
        /// </summary>
        public class CheckAuthorizationAttribute : ActionFilterAttribute
        {
            /// <summary>
            /// user Manager
            /// </summary>
            //public IUserManager _userManager { get; set; }
            /// <summary>
            /// On Action Executing
            /// </summary>
            /// <param name="actionContext"></param>
            public override void OnActionExecuting(ActionExecutingContext actionContext)
            {


                var email = ((System.Security.Claims.ClaimsIdentity)((Microsoft.AspNetCore.Mvc.ControllerBase)actionContext.Controller).User.Identity).NameClaimType;


                var rolx = actionContext.HttpContext.Request.Headers["Timestamp"].FirstOrDefault();
                string sessionToken = actionContext.HttpContext.Request.Headers["SessionToken"].FirstOrDefault();

                if (email == "99jzarra@gmail.com")
                    actionContext.Result =  new ObjectResult(new ResultClassModel() { Message = "Skip authentication is applied on this action.", Status = ActionStatus.Error });

            }
        }

        public enum ActionStatus
        {
            Successfull = 1,
            Error = 2,
            LoggedOut = 3,
            Unauthorized = 4,
            Failed = 5,
        }
        public class ActionOutputBase
        {
            public ActionStatus Status { get; set; }
            public String Message { get; set; }
            public List<String> Results { get; set; }
        }
        public class ActionOutput : ActionOutputBase
        {
        }
        public class ResultClassModel
        {
            public int ID { get; set; }
            public string sUID { get; set; }
            public String Message { get; set; }
            public ActionStatus Status { get; set; }
            public ResultClassModel() { }
            public ResultClassModel(ActionOutput result)
            {
                Message = result.Message;
                Status = result.Status;
            }
        }






        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
