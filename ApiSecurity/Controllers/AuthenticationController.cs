using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ApiSecurity.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly IConfiguration _config;

    //record- equivalent of creating a class and then having two properties, a username, password. so capital.
    // and also set up a constrcutor that takes in these 2 values and also modifying the two string value and a few other nice feature, so read only basically.

    //get the 3 values in secret json that will allows us to have info that we can work with
    // get values in generate token, create a constructor

    public AuthenticationController(IConfiguration config)
    {
        this._config = config;
    }
    public record AuthenticationData(string? Username, string? Password);
    public record UserData(int UserId, string UserName);
    // api/Authentication/token
    [HttpPost("token")]
    public ActionResult<string> Authenticate([FromBody] AuthenticationData data)
    {
        //validate creds.
        var user = ValidateCredential(data);

        if (user is null)
        {
            return Unauthorized();
        }

        var token = GenerateToken(user);

        return Ok(token);  //Ok is 200 object saying, successful action, value you want.
    }

    private string GenerateToken(UserData user)
    {
        //give user a simple way to authenticate every call without having to put in their login and pass every single time
        // we take those thinh we pass in then we use private key to create this secure symmrickey.  used to create a token
        // represent that you are who you say you are, can be steal, token have a short life span, few min, few hours,
        // secure token so they can't genereate their own tokens, to do that, we have to need a part of system based upon secure key that now one has access to.
        var secretKey = new SymmetricSecurityKey(
            Encoding.ASCII.GetBytes(
                _config.GetValue<string>("Authentication:SecretKey")));// inner most piece //nvigate using colon

        //sign token crdential, take our token information and then use our secret key to sign it like a digital sig
        //what does that is that if anythin changes inside token then it breaks everything because now it's not matching the signature, so kind of like a verificationstep
        var signingCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

        //claims
        // data points about the user that were verified 
        //verify 2 piece, id and username

        List<Claim> claims = new();
        claims.Add(new(JwtRegisteredClaimNames.Sub, user.UserId.ToString())); //way to identify the user    //standard claim that add to a claim file, in token we can have standard claim and custom claim. indsutry stanrard , expected.  subject-what identifies the user
        claims.Add(new(JwtRegisteredClaimNames.UniqueName, user.UserName)); //standard one unique name. 

        //build a token

        var token = new JwtSecurityToken(
            _config.GetValue<string>("Authentication:Issuer"),
            _config.GetValue<string>("Authentication:Audience"),
            claims,
            DateTime.UtcNow, // When this token becomes valid, universtal time coordinates
            DateTime.UtcNow.AddMinutes(1), // When the toekn will expire, we don't want token to last forever/ credentials.
                                           // idea of a regular token and refresh tokene, allows you to refresh things, token short, refresh token to allow you  to keep things going but refresh token essentiallny needs permission to be re issued. that way you can say it anytime you don't have access anymore, and it cancels out the token quickly. let go etc .
            signingCredentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
      }

    //an object can be null
    private UserData? ValidateCredential(AuthenticationData data)
    {
        // THIS IS NOT PRODUCTION CODE - THIS IS ONLY A DEMO- DO NOT USE IN REAL LIFE
        if (CompareValues(data.Username, "tcorey") &&
            CompareValues(data.Password, "Test123"))
        {
            return new UserData(1, data.Username!);
        }

        if (CompareValues(data.Username, "sstorm") &&
          CompareValues(data.Password, "Test123"))
        {
            return new UserData(2, data.Username!);
        }

        return null;

    }

    //allstring are nullable, clear when we expect it to be null.
    private bool CompareValues(string? actual, string expected)
    {
        if (actual is not null)
        {
            if (actual.Equals(expected))
            {
                return true;
            }
        }

        return false;
    }
}
