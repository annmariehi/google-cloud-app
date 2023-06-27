// Portfolio Assignment
// Ann Marie Hicks

const express = require('express');
const app = express();
const router = express.Router();
const { auth, requiresAuth } = require('express-openid-connect');

const dotenv  = require('dotenv').config();

const{ Datastore } = require('@google-cloud/datastore');
const datastore = new Datastore();

const json2html = require('json-to-html');
const bodyParser = require('body-parser');
const request = require('request');

const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');

// configuration for express-opened-connect
const config = {
    authorizationParams: {
        response_type: 'code',
        scope: 'openid profile email',
        auidence: process.env.AUDIENCE
    },
    authRequired: false,
    auth0Logout: true,
    secret: process.env.SECRET,
    baseURL: process.env.BASE_URL,
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    issuerBaseURL: process.env.ISSUER_URL
};

const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `https://${process.env.DOMAIN}/.well-known/jwks.json`
    }),
    // doesn't return an error if there isn't a token
    credentialsRequired: false,
    // Validate the audience and the issuer.
    issuer: `https://${process.env.DOMAIN}/`,
    algorithms: ['RS256']
});

function fromDatastore(item){
    item.id = item[Datastore.KEY].id;
    return item;
}

const USER = 'User';
const CONSOLE = 'Console';
const GAME = 'Game';

app.use(bodyParser.json());

// auth router attaches /login, /logout, and /callback routes to the baseURL
app.use(auth(config));

/* ------------- Begin Console Model Functions ------------- */

// creates and saves user entity in datastore when they log in
function post_user(name, email, auth0ID) {
    var key = datastore.key(USER);
    const new_user = {"name": name, "email": email, "auth0ID": auth0ID};
    const check_user = datastore.createQuery(USER).filter('auth0ID', '=', auth0ID);
    return datastore.runQuery(check_user).then ((entity) => {
        // if the user is already in the database, don't create new entry
        if(Object.keys(entity[0]).length > 0) {
            return entity[0];
        }
        return datastore.save({"key":key, "data":new_user}).then(() => {return key});
    });
}

// creates and saves console entity in datastore
function post_console(name, memory, storage, games, owner, http, host, url) {
    var key = datastore.key(CONSOLE);
	const new_console = {"name": name, "memory": memory, "storage": storage, "owner":owner, "games": games, "self": null};
    if (new_console.name == undefined || new_console.memory == undefined || new_console.storage == undefined ){
        return Promise.reject();
    }
	return datastore.save({"key":key, "data":new_console}).then(() => {
        // create self url and add it to console with new key.id
        var self_url = http + '://' + host + url + '/consoles/' + key.id;
        new_console.self = self_url;
        return datastore.save({ "key": key, "data": new_console })}).then(() => {
            return datastore.get(key).then((entity) => { return entity.map(fromDatastore); });
        });
}

// creates and saves game entity in datastore
function post_game(name, type, rating, http, host, url) {
    var key = datastore.key(GAME);
    const new_game = {"name": name, "type": type, "rating": rating, "console": null, "self": null};
    // reject if any required attributes are missing
    if (new_game.name == undefined || new_game.type == undefined || new_game.rating == undefined ) {
        return Promise.reject();
    }
    return datastore.save({"key":key, "data":new_game}).then(() => {
        // create self url and add it to game with new key.id
        var self_url = http + '://' + host + url + '/games/' + key.id;
        new_game.self = self_url;
        return datastore.save({ "key": key, "data": new_game })}).then(() => {
            return datastore.get(key).then((entity) => { return entity.map(fromDatastore); });
        });
}

// gets all the consoles for specified owner with valid jwt
function get_consoles(req, owner) {
    var num_q = datastore.createQuery(CONSOLE).filter('owner', '=', owner);
    return datastore.runQuery(num_q).then((consoles_len) => {
        var totalConsoles = Object.keys(consoles_len[0]).length;
        var q = datastore.createQuery(CONSOLE).filter('owner', '=', owner).limit(5);
        const results = {};
        results.totalConsoles = totalConsoles;
        if(Object.keys(req.query).includes("cursor")) {
            q = q.start(req.query.cursor);
        }
        return datastore.runQuery(q).then( (entities) => {
            results.consoles = entities[0].map(fromDatastore);
            if(entities[1].moreResults != datastore.NO_MORE_RESULTS ){
                results.next = req.protocol + "://" + req.get("host") + req.baseUrl + "/consoles?cursor=" + entities[1].endCursor;
            }
            return results;
        });
    })
}

// gets specific console with valid jwt
function get_console(console_id, owner) {
    const q = datastore.createQuery(CONSOLE).filter('owner', '=', owner)
                                            .filter('id', '=', console_id);
    return datastore.runQuery(q).then((consoles) => {
        if (consoles[0] === undefined || consoles[0] === null) {
            // no console found
            return consoles;
        } else {
            return consoles[0].map(fromDatastore);
        }
    });
}

// gets all the games
function get_games(req) {
    // first creates query to count total number of games
    var num_q = datastore.createQuery(GAME);
    return datastore.runQuery(num_q).then( (games_len) => {
        var totalGames = Object.keys(games_len[0]).length;
        // next query to set up pagination
        var q = datastore.createQuery(GAME).limit(5);
        const results = {};
        results.totalGames = totalGames;
        if(Object.keys(req.query).includes("cursor")){
            q = q.start(req.query.cursor);
        }
        return datastore.runQuery(q).then( (entities) => {
            results.games = entities[0].map(fromDatastore);
            if( entities[1].moreResults !== datastore.NO_MORE_RESULTS ) {
                results.next = req.protocol + "://" + req.get("host") + req.baseUrl + "/games?cursor=" + entities[1].endCursor;
            }
            return results;
	    });
    });
}

// gets specific game
function get_game(game_id) {
    const key = datastore.key([GAME, parseInt(game_id, 10)]);
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            // No entity found. Don't try to add the id attribute
            return entity;
        } else {
            return entity.map(fromDatastore);
        }
    });
}

// gets all the users
function get_users() {
    const q = datastore.createQuery(USER);
    return datastore.runQuery(q).then( (entities) => {
        return entities[0].map(fromDatastore);
    });
}

// edit console with PUT and valid jwt
function put_console(console_id, name, memory, storage, owner) {
    const games = []
    const key = datastore.key( [CONSOLE, parseInt(console_id, 10)] );
    const update_console = { "name": name, "memory": memory, "storage": storage, "owner": owner, "games": games , "self": null };
    if (update_console.name == undefined || update_console.memory == undefined || update_console.storage == undefined ){
        // reject if trying to update missing any of the required attributes
        return Promise.reject(new Error('missing_attributes'));
    }
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
         // No console with that id found, reject request
            return Promise.reject(new Error('no_id'));
        } else if (entity[0].owner != owner) {
            // user doesn't own console
            return Promise.reject(new Error('invalid_jwt'));
        } else {
            // copy over attributes that won't change
            update_console.self = entity[0].self;
            update_console.owner = entity[0].owner;
            update_console.games = entity[0].games;
            // save updated console and return
            return datastore.save({ "key": key, "data": update_console }).then(() => {
                return datastore.get(key).then((entity) => { return entity.map(fromDatastore); })
            });
        }
    });
}

// edit console with PATCH and valid jwt
function patch_console(console_id, name, memory, storage, owner) {
    const key = datastore.key( [CONSOLE, parseInt(console_id, 10)] );
    const update_console = { "name": name, "memory": memory, "storage": storage, "owner": owner, "games": null , "self": null };
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
         // No console with that id found, reject request
            return Promise.reject(new Error('no_id'));
        } else if (entity[0].owner != owner) {
            // user doesn't own console
            return Promise.reject(new Error('invalid_jwt'));
        } else {
            // copy over attributes that won't change
            update_console.self = entity[0].self;
            update_console.owner = entity[0].owner;
            update_console.games = entity[0].games;
            // if any attributes are undefined, fill it in with existing values from database
            if(update_console.name == undefined) {update_console.name = entity[0].name;}
            if(update_console.memory == undefined) {update_console.memory = entity[0].memory;}
            if(update_console.storage == undefined) {update_console.storage = entity[0].storage;}
            // save updated console and return
            return datastore.save({ "key": key, "data": update_console }).then(() => {
                return datastore.get(key).then((entity) => { return entity.map(fromDatastore); })
            });
        }
    });
}

// edit game with PUT
function put_game(game_id, name, type, rating) {
    const key = datastore.key( [GAME, parseInt(game_id, 10)] );
 const update_game = {"name": name, "type": type, "rating": rating, "console": null, "self": null};
    // reject if any required attributes are missing
    if (update_game.name == undefined || update_game.type == undefined || update_game.rating == undefined ) {
        return Promise.reject(new Error('missing_attributes'));
    }
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
         // No game with that id found, reject request
            return Promise.reject(new Error('no_id'));
        } else {
            // copy over attributes that won't change
            update_game.self = entity[0].self;
            update_game.console = entity[0].console;
            // save updated game and return
            return datastore.save({ "key": key, "data": update_game }).then(() => {
                return datastore.get(key).then((entity) => { return entity.map(fromDatastore); })
            });
        }
    });
}

// edit game with PATCH
function patch_game(game_id, name, type, rating) {
    const key = datastore.key( [GAME, parseInt(game_id, 10)] );
 const update_game = {"name": name, "type": type, "rating": rating, "console": null, "self": null};
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
         // No game with that id found, reject request
            return Promise.reject(new Error('no_id'));
        } else {
            // copy over attributes that won't change
            update_game.self = entity[0].self;
            update_game.console = entity[0].console;
            // if any attributes are undefined, fill it in with existing values from database
            if(update_game.name == undefined) {update_game.name = entity[0].name;}
            if(update_game.type == undefined) {update_game.type = entity[0].type;}
            if(update_game.rating == undefined) {update_game.rating = entity[0].rating;}
            // save updated game and return
            return datastore.save({ "key": key, "data": update_game }).then(() => {
                return datastore.get(key).then((entity) => { return entity.map(fromDatastore); })
            });
        }
    });
}

// add game to console
function put_game_console(console_id, game_id, owner, http, url) {
    const console_key = datastore.key([CONSOLE, parseInt(console_id,10)]);
    const game_key = datastore.key([GAME, parseInt(game_id,10)]);
    return datastore.get(console_key)
    .then( (consoles) => {
        if(consoles[0] === undefined || consoles[0] === null) {
            return Promise.reject(new Error('no_id')); // console doesn't exist
        } else if (consoles[0].owner != owner) {
            return Promise.reject(new Error('invalid_jwt')); // user doesn't own console
        }
        else {
            return datastore.get(game_key)
            .then ( (games) => {
                if(games[0] === undefined || games[0] === null) {
                    return Promise.reject(new Error('no_id')); // game doesn't exist
                }
                else if(games[0].console !== null) {
                    return Promise.reject(new Error('already_assigned'));
                }
                else {
                    // adding game to console.games and console to game.console
                    var game_self_url = http + '://' + url + '/games/' + game_id;
                    const add_game = {"id": game_id, "self": game_self_url};
                    var console_self_url = http + '://' + url + '/consoles/' + console_id;
                    const add_console = {"id": console_id, "self": console_self_url};
                    games[0].console = add_console;
                    consoles[0].games.push(add_game);
                    return datastore.save({"key": console_key, "data":consoles[0]}).then (
                        () => { return datastore.save({"key": game_key, "data":games[0]})}
                    );
                }
            });
        }
    });
}

// remove game from console if jwt matches console owner
function remove_game_console(console_id, game_id, owner) {
    const console_key = datastore.key([CONSOLE, parseInt(console_id,10)]);
    const game_key = datastore.key([GAME, parseInt(game_id,10)]);
    return datastore.get(console_key)
    .then( (consoles) => {
        if(consoles[0] === undefined || consoles[0] === null) {
            return Promise.reject(new Error('no_id')); // console doesn't exist
        } else if (consoles[0].owner != owner) {
            return Promise.reject(new Error('invalid_jwt')); // user doesn't own console
        } else {
            return datastore.get(game_key)
            .then ( (game) => {
                if(game[0] === undefined || game[0] === null) {
                    return Promise.reject(new Error('no_id')); // game doesn't exist
                }
                else if(game[0].console.id !== console_id) {
                    return Promise.reject(new Error('not_in_console')); // game not in console
                }
                else {
                    // remove console from game
                    game[0].console = null;
                    // remove game from console's games array
                    for(var i=0; i<consoles[0].games.length; i++) {
                        if(consoles[0].games[i].id === game_id) {
                            consoles[0].games.splice(i, 1);
                        }
                    }
                    return datastore.save({ "key": console_key, "data":consoles[0] }).then (
                        () => { return datastore.save({ "key": game_key, "data":game[0] }) }
                    );
                }
            });
        }
    });
}

// deletes console if the jwt owner matches the console owner
function delete_console(console_id, owner) {
    const key = datastore.key([CONSOLE, parseInt(console_id, 10)]);
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            // no console with that id found, reject request
            return Promise.reject(new Error('no_id'));
        } else {
            if (owner.sub == entity[0].owner) {
                return datastore.delete(key);
            } else {
                return Promise.reject(new Error('invalid_jwt'));
            }
        }
    });
}

// deletes game
function delete_game(game_id) {
    const key = datastore.key([GAME, parseInt(game_id, 10)]);
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return Promise.reject(new Error('no_id'));
        } else {
            return datastore.delete(key);
        }
    });
}

/* ------------- End Model Functions ------------- */

/* ------------- Begin Controller Functions ------------- */

// req.isAuthenticated is provided from the auth router
router.get('/', (req, res) => {
    if(req.oidc.isAuthenticated()) {
        post_user(req.oidc.user.nickname, req.oidc.user.name, req.oidc.user.sub).then((key) => {
        res.send (`
            <h1> Successfully Logged In! Hello ${req.oidc.user.nickname}</h1>
            <p> ID TOKEN: ${req.oidc.idToken} </p>
        `);
        });
    } else {
        res.send (`
            <h1> Welcome!</h1>
            <p> Please click the button below to log in or create your auth0 account. </p>
            <a href="/login">
            <button>Log In</button>
            </a>
        `);
    }
});

// returns all consoles of user if jwt is valid
router.get('/consoles', checkJwt, function(req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts) {
        res.status(406).send('Client must accept application/json response.');
    } else {
        if(req.user == undefined) {
            res.status(401).json({ 'Error': 'Unauthorized - Missing Authentication' });
        } else {
            const results = get_consoles(req, req.user.sub)
            .then( (results) => {
                res.status(200).json(results);
            }, (error) => {
                console.log(error);
                res.status(403).json({ 'Error': 'Invalid Authentication' });
            });
        }
    }
});

// returns all games
router.get('/games', function(req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts) {
        res.status(406).send('Client must accept application/json response.');
    } else {
        const games = get_games(req).then((games) => {
            res.status(200).json(games);
        });
    }
});

// returns all users
router.get('/users', function(req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts) {
        res.status(406).send('Client must accept application/json response.');
    } else {
        const users = get_users().then((users) => {
            res.status(200).json(users);
        });
    }
});

// returns specific game
router.get('/games/:game_id', function(req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts) {
        res.status(406).send('Client must accept application/json response.');
    } else {
        get_game(req.params.game_id).then(game => {
            if (game[0] === undefined || game[0] === null) {
                // The 0th element is undefined. This means there is no game with this game_id
                res.status(404).json({ 'Error': 'Not Found - No game with this game_id exists' });
            } else {
                // return game
                res.status(200).json(game);
            }
        });
    }
});

// returns specific console
router.get('/consoles/:console_id', checkJwt, function(req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts) {
        res.status(406).send('Client must accept application/json response.');
    } else {
        if(req.user == undefined) {
            res.status(401).json({ 'Error': 'Unauthorized - Missing Authentication' });
        } else {
            get_console(req.params.console_id, req.user.sub).then((consoles) => {
                if (consoles[0] === undefined || consoles[0] === null) {
                    // The 0th element is undefined. This means there is no console with this console_id
                    res.status(404).json({ 'Error': 'Not Found - No console with this console_id exists' });
                } else {
                    // return console
                    res.status(200).json(consoles);
                }
            });
        }
    }
});

// creates console if user is logged in
router.post('/consoles', checkJwt, function(req, res) {
    // reject if client doesn't accept application/json
    const accepts = req.accepts(['application/json']);
    if(!accepts) {
        res.status(406).send('Client must accept application/json response.');
    } else {
        const games = [];
        if(req.user == undefined) {
            res.status(401).json({ 'Error': 'Unauthorized - Missing Authentication' });
        } else {
            post_console(req.body.name, req.body.memory, req.body.storage, games, req.user.sub, req.protocol, req.get('host'), req.baseUrl)
            .then( (consoles) => {
                res.location(consoles[0].self).status(201).json(consoles[0]);
            });
        }
    }
});

// creates game, no JWT required
router.post('/games', function(req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts) {
        res.status(406).send('Client must accept application/json response.');
    } else {
        post_game(req.body.name, req.body.type, req.body.rating, req.protocol, req.get('host'), req.baseUrl)
        .then ( (game) => {
            res.location(game[0].self).status(201).json(game[0]);
        });
    }
});

// update console with PATCH, only works with valid JWT
router.patch('/consoles/:console_id', checkJwt, function(req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts) {
        res.status(406).send('Client must accept application/json response.');
    } else {
        if(req.user == undefined) {
            res.status(401).json({ 'Error': 'Unauthorized - Missing Authentication' });
        } else {
            patch_console(req.params.console_id, req.body.name, req.body.memory, req.body.storage, req.user.sub).then((consoles) => {
                res.location(consoles[0].self).status(204).json(consoles[0]);
            }, (error) => {
                if (error == 'Error: no_id') {
                    res.status(404).json({ 'Error': 'No console with this console_id exists'});
                } else if (error == 'Error: invalid_jwt') {
                    res.status(403).json({ 'Error': 'Forbidden - You do not own this console' });
                } else {
                    res.status(404).json({ 'Error': 'Help' });
                }
            });
        }
    }
});

// update console with PUT, only works with valid JWT
router.put('/consoles/:console_id', checkJwt, function(req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts) {
        res.status(406).send('Client must accept application/json response.');
    } else {
        if(req.user == undefined) {
            res.status(401).json({ 'Error': 'Unauthorized - Missing Authentication' });
        } else {
            put_console(req.params.console_id, req.body.name, req.body.memory, req.body.storage, req.user.sub).then((consoles) => {
                res.location(consoles[0].self).status(204).json(consoles[0]);
            }, (error) => {
                console.log(error);
                if (error == 'Error: no_id') {
                    res.status(404).json({ 'Error': 'No console with this console_id exists'});
                } else if (error == 'Error: invalid_jwt') {
                    res.status(403).json({ 'Error': 'Forbidden - You do not own this console' });
                } else if (error == 'Error: missing_attributes') {
                    res.status(405).json({ 'Error': 'Missing Attributes - must update all attributes with put request' });
                } else {
                    res.status(404).json({ 'Error': 'Help' });
                }
            });
        }
    }
});

// update game with PATCH
router.patch('/games/:game_id', function(req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts) {
        res.status(406).send('Client must accept application/json response.');
    } else {
        patch_game(req.params.game_id, req.body.name, req.body.type, req.body.rating).then((game) => {
            res.location(game[0].self).status(204).json(game[0]);
        }, (error) => {
            console.log(error);
            if (error == 'Error: no_id') {
                res.status(404).json({ 'Error': 'No game with this game_id exists'});
            } else {
                res.status(404).json({ 'Error': 'Help' });
            }
        });
    }
});

// update game with PUT
router.put('/games/:game_id', function(req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts) {
        res.status(406).send('Client must accept application/json response.');
    } else {
        put_game(req.params.game_id, req.body.name, req.body.type, req.body.rating).then((game) => {
            res.location(game[0].self).status(204).json(game[0]);
        }, (error) => {
            console.log(error);
            if (error == 'Error: no_id') {
                res.status(404).json({ 'Error': 'No game with this game_id exists' });
            } else if (error == 'Error: missing_attributes') {
                res.status(405).json({ 'Error': 'Missing Required Attributes' });
            } else {
                res.status(404).json({ 'Error': 'Help' });
            }
        });
    }
});

// add game to console, only works if user is owner of console
router.put('/consoles/:console_id/games/:game_id', checkJwt, function(req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts) {
        res.status(406).send('Client must accept application/json response.');
    } else {
        if(req.user == undefined) {
            res.status(401).json({ 'Error': 'Unauthorized - Missing Authentication' });
        } else {
            put_game_console(req.params.console_id, req.params.game_id, req.user.sub, req.protocol, req.get("host"))
            .then(
                (console_key) => {
                    res.status(204).json('game added to console');
                },
                (error) => {
                    console.log(error);
                    if(error == 'Error: no_id') {
                        res.status(404).json({ 'Error': 'Not Found - The specified console and/or game does not exist'});
                    } else if ( error == 'Error: already_assigned') {
                        res.status(403).json({ 'Error': 'Forbidden - This game has already been assigned to a console' });
                    } else if ( error == 'Error: invalid_jwt' ) {
                        res.status(403).json({ 'Error': 'Forbidden - You do not own this console' });
                    } else {
                        res.status(404).json({ 'Error': 'Unknown - Help' });
                    }
                }
            );
        }
    }
});

// remove game from console, only works if user is owner of console
router.delete('/consoles/:console_id/games/:game_id', checkJwt, function(req, res) {
    const accepts = req.accepts(['application/json']);
    if(!accepts) {
        res.status(406).send('Client must accept application/json response.');
    } else {
        if(req.user == undefined) {
            res.status(401).json({ 'Error': 'Unauthorized - Missing Authentication' });
        } else {
            remove_game_console(req.params.console_id, req.params.game_id, req.user.sub).then(() => {
                res.status(204).json('game removed');
            }, (error) => {
                console.log(error);
                if(error == 'Error: no_id'){
                    res.status(404).json({ 'Error': 'Not Found - No console with this console_id exists/no game with this game_id exists' });
                } else if(error == 'Error: invalid_jwt') {
                    res.status(403).json({ 'Error': 'Forbidden - Cannot remove game from unowned console' });
                } else if(error == 'Error: not_in_console') {
                    res.status(404).json({ 'Error': 'No game with this game_id in console' })
                } else {
                    res.status(404).json({ 'Error': 'Not Found' });
                }
            });
        }
    }
});

// Deletes the console from the console_id param only if the JWT matches the owner of the console
router.delete('/consoles/:console_id', checkJwt, function(req, res){
    // if a user is returned
    if(req.user != undefined) {
    delete_console(req.params.console_id, req.user).then(() => {
        res.status(204).json('console deleted')
    }, (error) => {
        console.log(error);
        if(error == 'Error: no_id'){
        res.status(404).json({ 'Error': 'Not Found - No console with this console_id exists' })
        } else if(error == 'Error: invalid_jwt') {
            res.status(403).json({ 'Error': 'Forbidden - Cannot delete console of other user' });
        } else {
            res.status(404).json({ 'Error': 'Not Found' });
        }
    })
    // if no valid JWT is returned
    } else {
        res.status(401).json({ 'Error': 'Unauthorized - Missing Authentication' });
    }
});

// Deletes the game, removes game from console
router.delete('/games/:game_id', function(req, res) {
    delete_game(req.params.game_id).then(() => {
            res.status(204).json('game deleted')
        }, (error) => {
            console.log(error);
            if(error == 'Error: no_id'){
                res.status(404).json({ 'Error': 'Not Found - No game with this game_id exists' })
            } else {
                res.status(404).json({ 'Error': 'Not Found' });
            }
        })
})

// Left incase you are suppose to be able to login through postman
  router.post('/postman-login', function(req, res){
    const username = req.body.username;
    const password = req.body.password;
    var options = { method: 'POST',
            url: `https://${process.env.DOMAIN}/oauth/token`,
            headers: { 'content-type': 'application/json' },
            body:
             { grant_type: 'password',
               username: username,
               password: password,
               client_id: process.env.CLIENT_ID,
               client_secret: process.env.CLIENT_SECRET },
            json: true };
    request(options, (error, response, body) => {
        if (error){
            res.status(500).send(error);
        } else {
            res.send(body);
        }
    });
});

/* ------------- End Controller Functions ------------- */

app.use('/', router);

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}...`);
});
