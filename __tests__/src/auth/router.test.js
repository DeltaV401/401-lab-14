'use strict';

process.env.SECRET = 'test';

const jwt = require('jsonwebtoken');

const Roles = require('../../../src/auth/roles-model.js');
const server = require('../../../src/app.js').server;
const supergoose = require('../../supergoose.js');

const mockRequest = supergoose(server);

let users = {
  owner: {username: 'owner', password: 'password', role: 'owner'},
  admin: {username: 'admin', password: 'password', role: 'admin'},
  editor: {username: 'editor', password: 'password', role: 'editor'},
  user: {username: 'user', password: 'password', role: 'user'},
};

beforeAll(async () => {
});


describe('Auth Router', () => {
  
  Object.keys(users).forEach( userType => {
    
    describe(`${userType} users`, () => {
      
      let encodedToken;
      let id;
      
      it('can create one', () => {
        return mockRequest.post('/signup')
          .send(users[userType])
          .then(results => {
            var token = jwt.decode(results.text);
            id = token.id;
            encodedToken = results.text;
            expect(token.id).toBeDefined();
            expect(token.capabilities).toBeDefined();
          });
      });

      it('can signin with basic', () => {
        return mockRequest.post('/signin')
          .auth(users[userType].username, users[userType].password)
          .then(results => {
            var token = jwt.decode(results.text);
            expect(token.id).toEqual(id);
            expect(token.capabilities).toBeDefined();
          });
      });

      it('can signin with bearer', () => {
        return mockRequest.post('/signin')
          .set('Authorization', `Bearer ${encodedToken}`)
          .then(results => {
            var token = jwt.decode(results.text);
            expect(token.id).toEqual(id);
            expect(token.capabilities).toBeDefined();
          });
      });

    });
    
  });
  
});

describe('New Route Tests', () => {
  it.each([
    // Arrange
    [200, '', 'get', '/public-stuff'],
    [401, 'charles', 'get', '/public-stuff'],
    [200, 'user', 'get', '/hidden-stuff'],
    [401, '', 'get', '/hidden-stuff'],
    [200, 'user', 'get', '/something-to-read'],
    [401, 'charles', 'get', '/something-to-read'],
    [200, 'admin', 'post', '/create-a-thing'],
    [401, 'user', 'post', '/create-a-thing'],
    [200, 'admin', 'put', '/update'],
    [401, 'user', 'put', '/update'],
    [200, 'admin', 'patch', '/jp'],
    [401, 'user', 'patch', '/jp'],
    [200, 'admin', 'delete', '/bye-bye'],
    [401, 'user', 'delete', '/bye-bye'],
    [200, 'owner', 'get', '/everything'],
    [401, 'admin', 'get', '/everything'],
  ])('should return %p when %s uses %p', (expectedStatus, userType, method, route) => {
    // Act
    return mockRequest[method](route)
      .auth(userType)
      .expect(expectedStatus);
  });
});