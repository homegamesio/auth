const Cognito = require('amazon-cognito-identity-js');

const login = (username, password) => new Promise((resolve, reject) => {

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

exports.handler = (event, context, callback) => {

    login(event.username, event.password).then(loginData => {
        callback(null, loginData);
    })

};

