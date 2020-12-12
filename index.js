const Cognito = require('amazon-cognito-identity-js');
const AWS = require('aws-sdk');

const login = (payload) => new Promise((resolve, reject) => {

    const username = payload.username;
    const password = payload.password;

    const authDetails = new Cognito.AuthenticationDetails({
        Username: username,
        Password: password
    });

    const poolData = {
        UserPoolId: process.env.COGNITO_USER_POOL_ID,
        ClientId: process.env.COGNITO_CLIENT_ID
    };

    const userPool = new Cognito.CognitoUserPool(poolData);

    const userData = {
        Username: username,
        Pool: userPool
    };

    const user = new Cognito.CognitoUser(userData);

    user.authenticateUser(authDetails, {
        onSuccess: (result) => {
            resolve({
                accessToken: result.getAccessToken().getJwtToken(),
                idToken: result.getIdToken().getJwtToken(),
                refreshToken: result.getRefreshToken().getToken()
            });
        },
        onFailure: (err) => {
            reject({
                error: err
            });
        }
    });
});

const verify = (payload) => new Promise((resolve, reject) => {
    //todo: move this logic to this package
    const lambda = new AWS.Lambda({ region: process.env.awsRegion });

    const params = {
        FunctionName: 'decode-jwt',
        Payload: JSON.stringify({
            token: payload.accessToken
        })
    };

    lambda.invoke(params, (err, _data) => {
        if (!_data) {
            reject('Failed to decode token');
        } else if (_data.Payload === 'false') {
            reject('invalid access token');
        } else if (err) {
            reject(err);
        }

        const data = JSON.parse(_data.Payload);

        if (data.username === payload.username) {
            resolve({
                success: true
            });
        } else {
            reject({
                success: false,
                message: 'JWT username does not match provided username'
            });
        }
    });

});

const inputHandlers = {
    authenticate: login,
    verify
};

exports.handler = (event, context, callback) => {

    if (inputHandlers[event.type]) {
        inputHandlers[event.type](event).then(response => {
            callback(null, response);
        });
    } else {
        callback('not found');
    }

};



