﻿using Microsoft.AspNetCore.Mvc;
using MyFace.Models.Request;
using MyFace.Models.Response;
using MyFace.Repositories;

namespace MyFace.Controllers
{
    [ApiController]
    [Route("/users")]
    public class UsersController : ControllerBase
    {
        private readonly IUsersRepo _users;

        public UsersController(IUsersRepo users)
        {
            _users = users;
        }


        [HttpGet("")]
        public ActionResult<UserListResponse> Search([FromQuery] UserSearchRequest searchRequest)
        {
            if (!IsAuthenticated())
            {
                return Unauthorized();
            }

            var users = _users.Search(searchRequest);
            var userCount = _users.Count(searchRequest);
            return UserListResponse.Create(searchRequest, users, userCount);
        }

    // [HttpGet("/login")]
    //     public bool login()
    //     {
    //         if (!IsAuthenticated())
    //         {
    //             return Unauthorized();
    //         } 
    //         return true;
    //     }

        [HttpGet("{id}")]
        public ActionResult<UserResponse> GetById([FromRoute] int id)
        {
            if (!IsAuthenticated())
            {
                return Unauthorized();
            }

            var user = _users.GetById(id);
            return new UserResponse(user);
        }

        [HttpPost("create")]
        public IActionResult Create([FromBody] CreateUserRequest newUser)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = _users.Create(newUser);

            var url = Url.Action("GetById", new { id = user.Id });
            var responseViewModel = new UserResponse(user);
            return Created(url, responseViewModel);
        }

        [HttpPatch("{id}/update")]
        public ActionResult<UserResponse> Update([FromRoute] int id, [FromBody] UpdateUserRequest update)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = _users.Update(id, update);
            return new UserResponse(user);
        }

        [HttpDelete("{id}")]
        public IActionResult Delete([FromRoute] int id)
        {
            _users.Delete(id);
            return Ok();
        }

        private bool IsAuthenticated()
        {
            var authHeader = HttpContext.Request.Headers["Authorization"].ToString();
            return _users.Authentication(authHeader);
        }
    }
}