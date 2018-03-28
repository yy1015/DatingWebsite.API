using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;
        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _config = config;
            _repo = repo;

        }
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody]UserForRegisterDto userForRegisterDto)
        {
            //throw new Exception("computer say no");
            if(!string.IsNullOrEmpty(userForRegisterDto.Username))
                userForRegisterDto.Username = userForRegisterDto.Username.ToLower();

            if (await _repo.Exist(userForRegisterDto.Username))
                ModelState.AddModelError("Username", "Username already exists");

            if (!ModelState.IsValid)
                return BadRequest(ModelState);



            var createToUser = new User
            {
                Username = userForRegisterDto.Username
            };

            var createdUser = await _repo.Register(createToUser, userForRegisterDto.Password);

            return StatusCode(201);

        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody]UserForLoginDto userForLoginDto)
        {
            var userForRepo = await _repo.LoginAsync(userForLoginDto.Username.ToLower(), userForLoginDto.Password);

            if (userForLoginDto == null)
            {
                return Unauthorized();
            }
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_config.GetSection("AppSettings:Token").Value);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                 {
                        new Claim(ClaimTypes.NameIdentifier, userForRepo.Id.ToString()),
                        new Claim(ClaimTypes.Name, userForRepo.Username )
                 }),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key)
                 , SecurityAlgorithms.HmacSha512Signature
                 )

            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);
            return Ok(new { tokenString });

        }
    }
}