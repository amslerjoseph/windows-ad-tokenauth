using AutoMapper;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace YOURNAMESPACEHERE
{

    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly IMapper _mapper;
        private readonly IConfiguration _config;

        public BinaryReader JwdRegisteredClaimNames { get; private set; }

        public AuthController(IMapper mapper, IConfiguration config)
        {
            _mapper = mapper;
            _config = config;
        }       

        [HttpPost("token")]
        public IActionResult CreateToken([FromBody] ADCredentials aduser)
        {
            try
            {
                const string LDAP_DOMAIN = "@Insert Domain here@";

                /************** THIS REQUIRES THE COMPATIBILITY PACK FROM ASP.NET *****************/
                using (var context = new PrincipalContext(ContextType.Domain, LDAP_DOMAIN, "service_acct_user", "service_acct_pswd"))
                {
                    if (context.ValidateCredentials(aduser.Username, aduser.Password))
                    {
                        var claims = new[]
                        {
                            new Claim(JwtRegisteredClaimNames.Sub, aduser.Username),
                            new Claim(JwtRegisteredClaimNames.Jti, new Guid().ToString())
                        };

                        //Your key is something you designate in your appsettings.json file. This should be something hard to guess.
                        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("Tokens:Key").Value));
                        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                        //Token expiration is set to 1 hour.
                        var token = new JwtSecurityToken(
                            issuer: _config.GetSection("Tokens:Issuer").Value,
                            audience: _config.GetSection("Tokens:Audience").Value,
                            claims: claims,
                            expires: DateTime.UtcNow.AddHours(1),
                            signingCredentials: creds
                        );

                        //returning an object with the jwt token as well as the expiration in a 200 Status Code.
                        return Ok(new
                        {
                            token = new JwtSecurityTokenHandler().WriteToken(token),
                            expiration = token.ValidTo
                        });
                    }
                    else
                    {
                        return BadRequest("Invalid Username or Password.");
                    }
                }


            }
            catch (Exception ex)
            {
                //throw your exception in a message or some way of notifying the right people.
                return BadRequest("An error has occured, please contact your system administrator. \n" + ex.message);
            }
        }
    }
}
