<?php
require __DIR__ . '/vendor/autoload.php';

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$app = AppFactory::create();
$app->addBodyParsingMiddleware();

$SECRET = "secretkey";

// DB connection (PDO)
$pdo = new PDO("mysql:host=localhost;dbname=color_api", "root", "");
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);


// ================= AUTH =================

// REGISTER
$app->post('/api/register', function (Request $request, Response $response) use ($pdo) {
    $data = $request->getParsedBody();
    $email = $data['email'];
    $password = password_hash($data['password'], PASSWORD_BCRYPT);

    $stmt = $pdo->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
    
    try {
        $stmt->execute([$email, $password]);
        $response->getBody()->write(json_encode(["message" => "User registered"]));
    } catch (Exception $e) {
        return $response->withStatus(500)->withBody(
            stream_for(json_encode(["error" => $e->getMessage()]))
        );
    }

    return $response->withHeader('Content-Type', 'application/json');
});


// LOGIN
$app->post('/api/login', function (Request $request, Response $response) use ($pdo, $SECRET) {
    $data = $request->getParsedBody();
    $email = $data['email'];
    $password = $data['password'];

    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $response->getBody()->write(json_encode(["message" => "User not found"]));
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
    }

    if (!password_verify($password, $user['password'])) {
        $response->getBody()->write(json_encode(["message" => "Invalid password"]));
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
    }

    $payload = ["id" => $user['id']];
    $token = JWT::encode($payload, $SECRET, 'HS256');

    $response->getBody()->write(json_encode([
        "message" => "Login successful",
        "token" => $token
    ]));

    return $response->withHeader('Content-Type', 'application/json');
});


// LOGOUT
$app->post('/api/logout', function (Request $request, Response $response) {
    $response->getBody()->write(json_encode([
        "message" => "Logout successful (client should delete token)"
    ]));
    return $response->withHeader('Content-Type', 'application/json');
});


// ================= COLORS API =================

// CREATE
$app->post('/api/colors', function (Request $request, Response $response) use ($pdo) {
    $data = $request->getParsedBody();

    $stmt = $pdo->prepare("INSERT INTO colors (color_name, hex_code) VALUES (?, ?)");
    
    try {
        $stmt->execute([$data['color_name'], $data['hex_code']]);
        $response->getBody()->write(json_encode(["message" => "Color added"]));
    } catch (Exception $e) {
        return $response->withStatus(500)->write(json_encode($e->getMessage()));
    }

    return $response->withHeader('Content-Type', 'application/json');
});


// GET ALL
$app->get('/api/colors', function (Request $request, Response $response) use ($pdo) {
    $stmt = $pdo->query("SELECT * FROM colors");
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $response->getBody()->write(json_encode($results));
    return $response->withHeader('Content-Type', 'application/json');
});


// GET BY ID
$app->get('/api/colors/{id}', function (Request $request, Response $response, $args) use ($pdo) {
    $stmt = $pdo->prepare("SELECT * FROM colors WHERE id = ?");
    $stmt->execute([$args['id']]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    $response->getBody()->write(json_encode($result));
    return $response->withHeader('Content-Type', 'application/json');
});


// UPDATE
$app->put('/api/colors', function (Request $request, Response $response) use ($pdo) {
    $data = $request->getParsedBody();

    $stmt = $pdo->prepare("UPDATE colors SET color_name=?, hex_code=? WHERE id=?");

    try {
        $stmt->execute([$data['color_name'], $data['hex_code'], $data['id']]);
        $response->getBody()->write(json_encode(["message" => "Color updated"]));
    } catch (Exception $e) {
        return $response->withStatus(500)->write(json_encode($e->getMessage()));
    }

    return $response->withHeader('Content-Type', 'application/json');
});


// DELETE
$app->delete('/api/colors', function (Request $request, Response $response) use ($pdo) {
    $data = $request->getParsedBody();

    $stmt = $pdo->prepare("DELETE FROM colors WHERE id=?");

    try {
        $stmt->execute([$data['id']]);
        $response->getBody()->write(json_encode(["message" => "Color deleted"]));
    } catch (Exception $e) {
        return $response->withStatus(500)->write(json_encode($e->getMessage()));
    }

    return $response->withHeader('Content-Type', 'application/json');
});


$app->run();